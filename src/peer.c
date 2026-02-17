#include "bgp/peer.h"
#include "bgp/bgp.h"
#include "bgp/fsm.h"
#include "bgp/msg.h"
#include "bgp/log.h"
#include "bgp/mpbgp.h"
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

bgp_peer_t* peer_create(event_loop_t* loop, const bgp_params_t* gp, const bgp_neighbor_cfg_t* nc){
  bgp_peer_t* p = calloc(1, sizeof(*p));
  if(!p) return NULL;

  p->loop           = loop;
  p->addr           = nc->addr;
  p->remote_asn_cfg = nc->remote_asn;
  strncpy(p->description, nc->description, sizeof(p->description)-1);

  p->local_asn       = gp->asn;
  p->local_id        = gp->router_id;
  p->local_hold      = nc->hold_time  ? nc->hold_time  : gp->hold_time;
  p->local_keepalive = nc->keepalive  ? nc->keepalive  : gp->keepalive;

  p->af_ipv4u_active = nc->af_ipv4u_active;
  p->af_ipv6u_active = nc->af_ipv6u_active;
  p->af_vpnv4_active = nc->af_vpnv4_active;
  p->af_evpn_active  = nc->af_evpn_active;
  p->af_vpls_active  = nc->af_vpls_active;

  strncpy(p->rmap_in,  nc->rmap_in,  sizeof(p->rmap_in)-1);
  strncpy(p->rmap_out, nc->rmap_out, sizeof(p->rmap_out)-1);
  p->is_rr_client = nc->is_rr_client;

  p->send_update4 = peer_send_update4;

  bgp_fsm_init(p);
  return p;
}

void peer_destroy(bgp_peer_t* p){
  if(!p) return;
  free(p);
}

void peer_start(bgp_peer_t* p){
  if(!p) return;
  log_msg(BGP_LOG_INFO, "Starting peer %s (remote-as %u) %s",
          inet_ntoa(p->addr), p->remote_asn_cfg, p->description);
  bgp_fsm_event(p, BGP_EVT_START);
}
