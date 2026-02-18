/*
 * IPv6 Routing Information Base implementation.
 * Parallel to rib.c but for IPv6 prefixes.
 * RFC 4271 best-path algorithm is identical for both IPv4 and IPv6.
 */

#include "bgp/rib6.h"
#include "bgp/peer.h"
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

static int pfx_eq(rib_prefix6_t a, rib_prefix6_t b)
{
  return memcmp(&a.pfx, &b.pfx, sizeof(struct in6_addr)) == 0 && a.plen == b.plen;
}

void rib6_init(rib6_t* r, uint32_t local_asn, struct in6_addr router_id)
{
  memset(r, 0, sizeof(*r));
  r->local_asn = local_asn;
  r->router_id = router_id;
}

void rib6_destroy(rib6_t* r)
{
  if (!r) return;
  for (int i = 0; i < r->entry_count; i++) {
    free(r->entries[i].paths);
    r->entries[i].paths = NULL;
  }
  free(r->entries);
  r->entries = NULL;
  r->entry_count = 0;
  r->entry_cap = 0;
}

int rib6_find_entry(const rib6_t* r, struct in6_addr pfx, uint8_t plen)
{
  rib_prefix6_t k = {.pfx = pfx, .plen = plen};
  for (int i = 0; i < r->entry_count; i++) {
    if (pfx_eq(r->entries[i].pfx, k)) return i;
  }
  return -1;
}

static int rib6_get_or_add_entry(rib6_t* r, struct in6_addr pfx, uint8_t plen)
{
  int idx = rib6_find_entry(r, pfx, plen);
  if (idx >= 0) return idx;

  if (r->entry_count == r->entry_cap) {
    int ncap = (r->entry_cap == 0) ? 64 : r->entry_cap * 2;
    rib_entry6_t* n = (rib_entry6_t*)realloc(r->entries, (size_t)ncap * sizeof(rib_entry6_t));
    if (!n) return -1;
    r->entries = n;
    r->entry_cap = ncap;
  }

  idx = r->entry_count++;
  memset(&r->entries[idx], 0, sizeof(r->entries[idx]));
  r->entries[idx].pfx.pfx = pfx;
  r->entries[idx].pfx.plen = plen;
  r->entries[idx].best_index = -1;
  return idx;
}

void rib6_withdraw(rib6_t* r, bgp_peer_t* from, struct in6_addr pfx, uint8_t plen)
{
  int e = rib6_find_entry(r, pfx, plen);
  if (e < 0) return;
  rib_entry6_t* re = &r->entries[e];
  for (int i = 0; i < re->path_count;) {
    if (re->paths[i].from == from) {
      memmove(&re->paths[i], &re->paths[i+1], (size_t)(re->path_count - i - 1) * sizeof(re->paths[0]));
      re->path_count--;
      continue;
    }
    i++;
  }
}

void rib6_add_or_replace(rib6_t* r, bgp_peer_t* from, struct in6_addr pfx, uint8_t plen,
                         const bgp_attrs_t* a, struct in6_addr next_hop)
{
  int e = rib6_get_or_add_entry(r, pfx, plen);
  if (e < 0) return;
  rib_entry6_t* re = &r->entries[e];

  for (int i = 0; i < re->path_count; i++) {
    if (re->paths[i].from == from) {
      re->paths[i].attrs = *a;
      re->paths[i].next_hop = next_hop;
      return;
    }
  }

  if (re->path_count == re->path_cap) {
    int ncap = (re->path_cap == 0) ? 8 : re->path_cap * 2;
    rib_path6_t* n = (rib_path6_t*)realloc(re->paths, (size_t)ncap * sizeof(rib_path6_t));
    if (!n) return;
    re->paths = n;
    re->path_cap = ncap;
  }

  re->paths[re->path_count].pfx.pfx = pfx;
  re->paths[re->path_count].pfx.plen = plen;
  re->paths[re->path_count].from = from;
  re->paths[re->path_count].attrs = *a;
  re->paths[re->path_count].next_hop = next_hop;
  re->path_count++;
}

/* Return true if peer's remote ASN differs from local_asn (eBGP). */
static bool path_is_ebgp(const rib_path6_t* p, uint32_t local_asn)
{
  if (!p->from || local_asn == 0) return false;
  return p->from->remote_asn != local_asn;
}

/*
 * RFC 4271 §9.1.2 full best-path comparison — returns non-zero if 'a' is
 * strictly preferred over 'b'.
 *
 * Order:
 *  1. Highest LOCAL_PREF (iBGP only; default 100)
 *  2. Shortest AS_PATH length
 *  3. Lowest ORIGIN (IGP < EGP < INCOMPLETE)
 *  4. Lowest MED (only when from same AS)
 *  5. eBGP preferred over iBGP
 *  6. Lowest BGP next-hop router-id (tie-break)
 */
static int better(const rib6_t* rib, const rib_path6_t* a, const rib_path6_t* b)
{
  /* 1. Highest LOCAL_PREF */
  uint32_t lp_a = a->attrs.has_local_pref ? a->attrs.local_pref : 100;
  uint32_t lp_b = b->attrs.has_local_pref ? b->attrs.local_pref : 100;
  if (lp_a != lp_b) return (lp_a > lp_b);

  /* 2. Shortest AS_PATH */
  int asp_a = a->attrs.has_as_path ? a->attrs.as_path_len : 0;
  int asp_b = b->attrs.has_as_path ? b->attrs.as_path_len : 0;
  if (asp_a != asp_b) return (asp_a < asp_b);

  /* 3. Lowest ORIGIN (0=IGP 1=EGP 2=INCOMPLETE) */
  if (a->attrs.origin != b->attrs.origin) return (a->attrs.origin < b->attrs.origin);

  /* 4. Lowest MED (compare only when from same neighbouring AS) */
  {
    uint32_t asn_a = (a->from) ? a->from->remote_asn : 0;
    uint32_t asn_b = (b->from) ? b->from->remote_asn : 0;
    if (asn_a == asn_b) {
      uint32_t med_a = a->attrs.has_med ? a->attrs.med : 0;
      uint32_t med_b = b->attrs.has_med ? b->attrs.med : 0;
      if (med_a != med_b) return (med_a < med_b);
    }
  }

  /* 5. eBGP preferred over iBGP */
  bool ebgp_a = path_is_ebgp(a, rib->local_asn);
  bool ebgp_b = path_is_ebgp(b, rib->local_asn);
  if (ebgp_a != ebgp_b) return (int)ebgp_a;

  /* 6. Lowest router-id (peer remote_id used as tie-breaker) */
  /* For IPv6, use the last 4 bytes of router_id if available, otherwise use 0 */
  uint32_t rid_a = a->from ? a->from->remote_id.s_addr : 0;
  uint32_t rid_b = b->from ? b->from->remote_id.s_addr : 0;
  if (rid_a != rid_b) return (rid_a < rid_b);

  return 0;
}

void rib6_recompute_best(rib6_t* r, int entry_index)
{
  if (entry_index < 0 || entry_index >= r->entry_count) return;
  rib_entry6_t* re = &r->entries[entry_index];
  int best = -1;

  for (int i = 0; i < re->path_count; i++) {
    if (best < 0) {
      best = i;
      continue;
    }
    if (better(r, &re->paths[i], &re->paths[best])) best = i;
  }
  re->best_index = best;
}
