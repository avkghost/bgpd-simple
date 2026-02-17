#include "bgp/core_vpn.h"
#include "bgp/extcomm.h"
#include "bgp/netlink.h"
#include "bgp/mpls.h"
#include "bgp/log.h"
#include <arpa/inet.h>
#include <stdlib.h>

static vrf_instance_t* vrf_by_import_rt(bgp_core_t* c, const extcomm_set_t* rts){
  for(int i=0;i<c->vrf_inst_count;i++){
    vrf_instance_t* v = &c->vrf_inst[i];
    if(rt_sets_intersect(rts, v->cfg.import_rts, v->cfg.import_count)){
      return v; // baseline: first match. Extend to multiple VRFs if needed.
    }
  }
  return NULL;
}

void core_on_vpnv4(bgp_core_t* c, bgp_peer_t* from, const vpnv4_update_t* vu){
  // Withdraws
  for(int i=0;i<vu->withdraw_count;i++){
    const vpnv4_nlri_t* n = &vu->withdraw[i];

    vrf_instance_t* v = vrf_by_import_rt(c, &vu->rts);
    if(!v || v->cfg.table_id == 0) continue;

    // Delete from Linux VRF table (plain v4 delete is table-aware in your netlink_linux.c)
    (void)nl_route_delete_v4(n->pfx, n->plen, v->cfg.table_id);

    // Keep internal per-VRF RIB consistent
    rib4_withdraw(&v->rib4, from, n->pfx, n->plen);
    int ei = rib4_find_entry(&v->rib4, n->pfx, n->plen);
    if(ei >= 0) (void)rib4_recompute_best(&v->rib4, ei);
  }

  // Announce
  for(int i=0;i<vu->nlri_count;i++){
    const vpnv4_nlri_t* n = &vu->nlri[i];
    if(!vu->has_nh) continue;

    vrf_instance_t* v = vrf_by_import_rt(c, &vu->rts);
    if(!v || v->cfg.table_id == 0) continue;

    // MPLS-encap install into VRF table:
    // ip route replace <pfx>/<plen> via <nh> encap mpls <label> table <table_id>
    uint32_t lab = n->label;
    (void)nl_route_replace_v4_mpls_encap(n->pfx, n->plen, vu->nh, &lab, 1, v->cfg.table_id);

    // Store in per-VRF RIB (optional)
    bgp_attrs_t a = vu->attrs;
    a.has_next_hop = true;
    a.next_hop = vu->nh;

    rib4_add_or_replace(&v->rib4, from, n->pfx, n->plen, &a);
    int ei = rib4_find_entry(&v->rib4, n->pfx, n->plen);
    if(ei >= 0) (void)rib4_recompute_best(&v->rib4, ei);
  }
}
