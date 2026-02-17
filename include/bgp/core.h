#pragma once
#include "bgp/event.h"
#include <netinet/in.h>
#include "bgp/rib.h"
#include "bgp/policy.h"
#include "bgp/update.h"
#include "bgp/vrf.h"
#include "bgp/vpn.h"

typedef struct bgp_peer bgp_peer_t;

typedef struct {
  vrf_t cfg;
  rib4_t rib4;
} vrf_instance_t;

typedef struct bgp_core {
  rib4_t rib;
  policy_db_t pol;

  struct in_addr router_id;
  struct in_addr cluster_id;
  int fib_table;
  uint32_t local_asn;

  bgp_peer_t* peers[64];
  int peer_count;

  vrf_instance_t* vrf_inst;  /* heap-allocated */
  int vrf_inst_count;
  int vrf_inst_cap;

  /* Passive TCP listener */
  int listen_fd;        /* -1 if not listening */
  event_loop_t* loop;   /* shared event loop for passive accept */

  /**
   * Optional callback invoked at the end of core_on_established() to
   * advertise locally-originated networks and the full RIB to the new peer.
   * Set by bgp_start() to bgp_on_peer_established().
   *
   * @param ud   Opaque user data (bgp_global_t* in practice).
   * @param p    The peer that just reached ESTABLISHED.
   */
  void (*on_established_cb)(void* ud, bgp_peer_t* p);
  void* on_established_ud;
} bgp_core_t;

void core_init(bgp_core_t* c);
void core_destroy(bgp_core_t* c);
void core_set_ids(bgp_core_t* c, struct in_addr router_id, struct in_addr cluster_id);
void core_set_fib_table(bgp_core_t* c, int table);

void core_register_peer(bgp_core_t* c, bgp_peer_t* p);

void core_on_update4(bgp_core_t* c, bgp_peer_t* from, const bgp_update4_t* up);
void core_on_vpnv4(bgp_core_t* c, bgp_peer_t* from, const vpnv4_update_t* vu);
/* raw_attrs / raw_attrs_len: the raw path-attribute bytes from the UPDATE
 * (needed to extract MP_REACH / MP_UNREACH NLRI blobs for AFI 25). */
void core_on_evpn_update(bgp_core_t* c, bgp_peer_t* from,
                         const uint8_t* raw_attrs, int raw_attrs_len);
void core_on_vpls_update(bgp_core_t* c, bgp_peer_t* from,
                         const uint8_t* raw_attrs, int raw_attrs_len);
vrf_instance_t* core_get_vrf(bgp_core_t* c, const char* name, int create);

// Called by FSM when peer session goes down (withdraw all routes from peer)
void core_on_peer_down(bgp_core_t* c, bgp_peer_t* p);

/*
 * Start passive TCP listen on BGP port.  When a new connection arrives,
 * look up a configured peer by source IP and call bgp_fsm_accept().
 * loop: the event loop to register the accept fd with.
 */
int core_start_listen(bgp_core_t* c, event_loop_t* loop, uint16_t port);

// Called by FSM when peer enters ESTABLISHED
void core_on_established(bgp_core_t* c, bgp_peer_t* p);
void core_advertise_evpn_type5_for_networks(bgp_core_t* c, bgp_peer_t* p,
                                           const struct in_addr* pfx, uint8_t plen);
