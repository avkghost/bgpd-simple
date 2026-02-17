/* src/update6.c — IPv6 unicast MP-BGP UPDATE encode/decode (RFC 4760) */

#include "bgp/update6.h"
#include "bgp/mp_update.h"
#include "bgp/nlri.h"
#include "bgp/attrs.h"
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

/* ── helpers ──────────────────────────────────────────────────────────── */

static int get_u16(const uint8_t* p){ return (p[0] << 8) | p[1]; }

void update6_init(bgp_update6_t* u)
{
  memset(u, 0, sizeof(*u));
  attrs_init(&u->attrs);
}

/* ── RX decode ────────────────────────────────────────────────────────── */

/*
 * Walk the path-attributes block looking for MP_REACH_NLRI (14) and
 * MP_UNREACH_NLRI (15) for AFI=2 SAFI=1.
 */
static int decode_mp_attrs6(bgp_update6_t* u,
                             const uint8_t* attrs, int alen)
{
  int off = 0;
  while (off < alen) {
    if (off + 2 > alen) return -1;
    uint8_t flags = attrs[off];
    uint8_t code  = attrs[off + 1];
    off += 2;

    bool extlen = (flags & 0x10) != 0;
    int  vlen   = 0;
    if (extlen) {
      if (off + 2 > alen) return -1;
      vlen  = get_u16(attrs + off);
      off  += 2;
    } else {
      if (off + 1 > alen) return -1;
      vlen  = attrs[off++];
    }
    if (off + vlen > alen) return -1;
    const uint8_t* v = attrs + off;

    if (code == 14 && vlen >= 4) {
      /* MP_REACH_NLRI: AFI(2) SAFI(1) NHLen(1) NH NLRIs */
      uint16_t afi  = (uint16_t)get_u16(v);
      uint8_t  safi = v[2];
      if (afi == 2 && safi == 1) {
        int p = 3;
        uint8_t nhlen = v[p++];
        if (p + nhlen > vlen) return -1;
        /* accept 16-byte global or 32-byte (global + link-local) */
        if (nhlen >= 16) {
          memcpy(&u->next_hop, v + p, 16);
          u->has_nh = true;
        }
        p += nhlen;
        /* SNPA count (skip) */
        if (p >= vlen) return -1;
        uint8_t snpa = v[p++];
        for (int s = 0; s < (int)snpa; s++) {
          if (p >= vlen) return -1;
          uint8_t slen = v[p++];
          p += (slen + 1) / 2;   /* SNPA octets */
          if (p > vlen) return -1;
        }
        /* NLRI */
        int nlri_len = vlen - p;
        if (nlri_len > 0) {
          if (nlri_decode6(u->nlri, BGP_UPDATE6_MAX_PREFIXES,
                           &u->nlri_count, v + p, nlri_len) < 0)
            return -1;
        }
      }
    } else if (code == 15 && vlen >= 3) {
      /* MP_UNREACH_NLRI: AFI(2) SAFI(1) withdrawn */
      uint16_t afi  = (uint16_t)get_u16(v);
      uint8_t  safi = v[2];
      if (afi == 2 && safi == 1) {
        int nlri_len = vlen - 3;
        if (nlri_len > 0) {
          if (nlri_decode6(u->withdrawn, BGP_UPDATE6_MAX_PREFIXES,
                           &u->withdrawn_count, v + 3, nlri_len) < 0)
            return -1;
        }
      }
    }

    off += vlen;
  }
  return 0;
}

int update6_decode(bgp_update6_t* u, const uint8_t* msg, int msglen,
                   bool is_ebgp)
{
  update6_init(u);
  if (msglen < 19 + 4) return -1;

  const uint8_t* pay    = msg + 19;
  int            paylen = msglen - 19;
  int            off    = 0;

  /* withdrawn routes (classic — always 0 for IPv6) */
  if (off + 2 > paylen) return -1;
  int wlen = get_u16(pay + off); off += 2;
  if (off + wlen > paylen) return -1;
  off += wlen;

  /* path attributes */
  if (off + 2 > paylen) return -1;
  int alen = get_u16(pay + off); off += 2;
  if (off + alen > paylen) return -1;

  if (attrs_decode(&u->attrs, pay + off, alen, is_ebgp) < 0) return -1;
  if (decode_mp_attrs6(u, pay + off, alen) < 0) return -1;

  return 0;
}

/* ── TX encode ────────────────────────────────────────────────────────── */

int update6_encode_reach(uint8_t* out, int outlen,
                         const struct in6_addr* nh6,
                         const nlri_pfx6_t* pfx, int pfx_count,
                         const bgp_attrs_t* attrs,
                         bool is_ebgp, uint32_t local_asn)
{
  if (!out || !nh6 || !pfx || pfx_count <= 0) return -1;

  /* Build NLRI blob */
  uint8_t nlri_buf[4096];
  int nlri_len = nlri_encode6(nlri_buf, (int)sizeof(nlri_buf), pfx, pfx_count);
  if (nlri_len < 0) return -1;

  /* Next-hop: 16-byte global */
  uint8_t nh_buf[16];
  memcpy(nh_buf, nh6, 16);

  mp_reach_t r;
  memset(&r, 0, sizeof(r));
  r.afi     = 2;   /* IPv6 */
  r.safi    = 1;   /* unicast */
  r.nh_len  = 16;
  memcpy(r.nh, nh_buf, 16);
  r.nlri    = nlri_buf;
  r.nlri_len = (uint16_t)nlri_len;

  return mp_update_encode(out, outlen, attrs, is_ebgp, local_asn, &r, NULL);
}

int update6_encode_unreach(uint8_t* out, int outlen,
                           const nlri_pfx6_t* pfx, int pfx_count,
                           bool is_ebgp, uint32_t local_asn)
{
  if (!out || !pfx || pfx_count <= 0) return -1;

  uint8_t nlri_buf[4096];
  int nlri_len = nlri_encode6(nlri_buf, (int)sizeof(nlri_buf), pfx, pfx_count);
  if (nlri_len < 0) return -1;

  mp_unreach_t u;
  memset(&u, 0, sizeof(u));
  u.afi          = 2;
  u.safi         = 1;
  u.withdrawn    = nlri_buf;
  u.withdrawn_len = (uint16_t)nlri_len;

  return mp_update_encode(out, outlen, NULL, is_ebgp, local_asn, NULL, &u);
}
