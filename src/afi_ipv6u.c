// src/afi_ipv6u.c
// IPv6 unicast export helpers (parallel to afi_ipv4u.c).
// Uses rib6_t / rib_entry6_t from include/bgp/rib6.h and peer->send_update6().

#include "bgp/core.h"
#include "bgp/peer.h"
#include "bgp/rib6.h"
#include "bgp/attrs.h"
#include "bgp/policy.h"
#include "bgp/log.h"

#include <arpa/inet.h>
#include <string.h>

static int peer_is_established(const bgp_peer_t* p){
  return p && p->st == BGP_ESTABLISHED && p->fd >= 0;
}

static const rib_path6_t* rib6_best_path(const rib_entry6_t* e){
  if(!e) return NULL;
  if(e->best_index < 0) return NULL;
  if(e->best_index >= e->path_count) return NULL;
  return &e->paths[e->best_index];
}

int afi_ipv6u_withdraw_one(bgp_peer_t* p, struct in6_addr pfx, uint8_t plen){
  if(!p || !p->send_update6) return -1;
  return p->send_update6(p, &pfx, plen, NULL, /*withdraw*/true);
}

int afi_ipv6u_announce_one(bgp_peer_t* p, struct in6_addr pfx, uint8_t plen, const bgp_attrs_t* a){
  if(!p || !p->send_update6 || !a) return -1;
  return p->send_update6(p, &pfx, plen, a, /*withdraw*/false);
}

static void export_entry_best_to_peer(bgp_core_t* c, bgp_peer_t* p,
                                       const rib_entry6_t* e){
  if(!peer_is_established(p) || !e) return;

  const rib_path6_t* best = rib6_best_path(e);
  if(!best){
    /* No best path => withdraw */
    (void)afi_ipv6u_withdraw_one(p, e->pfx.pfx, e->pfx.plen);
    return;
  }

  bgp_attrs_t a = best->attrs;

  /* Apply outbound route-map before sending to this peer */
  if(c && !route_map_apply_v6(&c->pol, p->rmap_out,
                              e->pfx.pfx, e->pfx.plen, &a))
    return;   /* route-map denied */

  (void)afi_ipv6u_announce_one(p, e->pfx.pfx, e->pfx.plen, &a);
}

/*
 * Export full IPv6u RIB to a single peer (used on session up).
 * This is a simple "dump best-paths" pass.
 */
void afi_ipv6u_advertise_peer(bgp_core_t* c, bgp_peer_t* p){
  if(!c || !p) return;
  if(!peer_is_established(p)) return;

  for(int i = 0; i < c->rib6.entry_count; i++){
    const rib_entry6_t* e = &c->rib6.entries[i];
    export_entry_best_to_peer(c, p, e);
  }
}

/*
 * Export a single IPv6 prefix to all established peers.
 * Call this after rib6_recompute_best() for that prefix.
 */
void afi_ipv6u_export_prefix_all(bgp_core_t* c, struct in6_addr pfx, uint8_t plen){
  if(!c) return;

  int ei = rib6_find_entry(&c->rib6, pfx, plen);
  if(ei < 0) return;

  const rib_entry6_t* e = &c->rib6.entries[ei];

  // Core stores peers as pointers (based on core_register_peer() usage).
  for(int i = 0; i < c->peer_count; i++){
    bgp_peer_t* p = c->peers[i];
    export_entry_best_to_peer(c, p, e);
  }
}

/*
 * Export everything to all established peers (manual resync).
 */
void afi_ipv6u_export_all(bgp_core_t* c){
  if(!c) return;

  for(int i = 0; i < c->peer_count; i++){
    bgp_peer_t* p = c->peers[i];
    afi_ipv6u_advertise_peer(c, p);
  }
}
