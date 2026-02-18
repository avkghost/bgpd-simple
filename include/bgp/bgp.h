#pragma once
#include "bgp/policy.h"
#include "bgp/vrf.h"
#include "bgp/peer.h"
#include "bgp/rib.h"
#include "bgp/interface.h"
#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>

#define BGP_PORT 179

typedef struct bgp_global bgp_global_t;
typedef struct bgp_peer   bgp_peer_t;

typedef struct {
  uint32_t asn;
  struct in_addr router_id;
  uint16_t hold_time;
  uint16_t keepalive;
} bgp_params_t;

typedef struct {
  struct in_addr addr;
  uint32_t remote_asn;
  char description[64];
  uint16_t hold_time;
  uint16_t keepalive;

  bool af_ipv4u_active;
  bool af_ipv6u_active;
  bool af_vpnv4_active;
  bool af_evpn_active;
  bool af_vpls_active;   // NEW: AFI=25 SAFI=65

  char rmap_in[64];
  char rmap_out[64];
  int is_rr_client;
} bgp_neighbor_cfg_t;

typedef struct {
  uint8_t af;                  /* 1=IPv4 global, 2=IPv6 global, 3=VPNv4 */
  uint8_t plen;               /* 0-32 for IPv4, 0-128 for IPv6 */
  union {
    struct in_addr  addr4;     /* IPv4 address (af=1 or af=3) */
    struct in6_addr addr6;     /* IPv6 address (af=2) */
  } prefix;
  char vrf_name[64];          /* empty for global (af=1,2), VRF name for VPNv4 (af=3) */
  uint32_t label;             /* MPLS label (future: EVPN/VPLS) */
} bgp_network_t;

/*
 * Persistent static route from config:
 *   ip route <prefix>/<plen> via <nexthop> [dev <ifname>] [table <id>]
 *   ip route <prefix>/<plen> dev <ifname>  [table <id>]
 *
 * If nexthop.s_addr == 0 and ifname is set, the route is an interface route.
 * table == 0 means the main table (254).
 */
typedef struct {
  struct in_addr prefix;
  uint8_t        plen;
  struct in_addr nexthop;    /* 0.0.0.0 = interface-only route */
  char           ifname[16]; /* empty = gateway route */
  int            table;      /* 0 = main (254) */
} static_route_t;

typedef struct {
  bgp_params_t params;
  bgp_neighbor_cfg_t neighbors[64];
  int neighbor_count;

  bgp_network_t networks[256];
  int network_count;

  static_route_t static_routes[256];
  int static_route_count;

  struct in_addr cluster_id;
  policy_db_t policy;

  vrf_db_t vrfs;

  interface_cfg_t interfaces[64];
  int interface_count;

  char cli_listen[256];        /* CLI socket path: "unix:/path" or "host:port" */

  bool default_ipv4_unicast;   /* true = auto-activate IPv4 unicast (default), false = disabled */

//  int fib_table;

} bgp_config_t;

bgp_global_t* bgp_create(void);
void bgp_destroy(bgp_global_t* g);

int bgp_load_config(bgp_config_t* out, const char* path);

int  bgp_start(bgp_global_t* g, const bgp_config_t* cfg, bool daemonize);
int  bgp_run(bgp_global_t* g);
void bgp_stop(bgp_global_t* g);

/**
 * @brief Get the event loop from bgp_global_t (for signal handling, etc.)
 * @note The returned pointer is opaque (event_loop_t is defined elsewhere)
 */
void* bgp_get_event_loop(bgp_global_t* g);

/**
 * @brief Advertise locally-originated networks and the full IPv4 unicast RIB
 *        to a peer that has just entered ESTABLISHED state.
 *
 * Must be called from core_on_established() after EVPN/VPLS advertisement.
 * @note core.c includes bgp.h to call this.
 */
void bgp_on_peer_established(bgp_global_t* g, bgp_peer_t* p);
