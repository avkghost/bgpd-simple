#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <netinet/in.h>

#include "bgp/fsm.h"
#include "bgp/event.h"
#include "bgp/attrs.h"
#include "bgp/mpbgp.h"

typedef struct bgp_core bgp_core_t;

typedef struct bgp_peer {
  // config identity
  struct in_addr addr;
  uint32_t remote_asn_cfg;
  char description[64];

  // local config
  uint32_t local_asn;
  struct in_addr local_id;
  uint16_t local_hold;       // seconds
  uint16_t local_keepalive;  // seconds

  // negotiated/learned
  uint32_t remote_asn;       // from OPEN (legacy 16-bit unless AS4 capability used later)
  struct in_addr remote_id;
  uint16_t negotiated_hold;  // seconds

  // policy attachment
  char rmap_in[64];
  char rmap_out[64];

  // RR flags
  int is_rr_client;

  // io
  int fd;
  uint8_t rxbuf[4096];
  size_t rxlen;

  // FSM
  bgp_state_t st;
  event_loop_t* loop;

  int keepalive_timer_id;
  int hold_timer_id;

  // reconnect/backoff
  int reconnect_timer_id;
  uint64_t reconnect_backoff_ms;
  uint64_t reconnect_backoff_min;
  uint64_t reconnect_backoff_max;
  bool want_reconnect;

  // Graceful Restart (RFC 4724)
  int  gr_stale_timer_id;   // timer id for stale-route cleanup
  bool gr_stale_active;     // true while stale routes are being held

  // backref
  bgp_core_t* core;

  // function pointers (owned by msg/core)
  int (*send_update4)(struct bgp_peer* p,
                      const struct in_addr* pfx, uint8_t plen,
                      const bgp_attrs_t* a,
                      bool withdraw);

  int (*send_update6)(struct bgp_peer* p,
                      const struct in6_addr* pfx, uint8_t plen,
                      const bgp_attrs_t* a,
                      bool withdraw);

  void (*fsm_event)(struct bgp_peer*, int ev);

  // negotiated capabilities parsed from peer OPEN
  bgp_caps_t caps;

  // AF activation (from config: neighbor ... activate under address-family)
  bool af_ipv4u_active;
  bool af_ipv6u_active;
  bool af_vpnv4_active;
  bool af_evpn_active;  // AFI 25/70
  bool af_vpls_active;  // AFI 25/65

} bgp_peer_t;
