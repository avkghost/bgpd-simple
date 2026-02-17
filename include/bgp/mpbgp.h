#pragma once
#include <stdint.h>
#include <stdbool.h>

typedef struct {
  // MP-BGP families negotiated
  bool mp_ipv4u;   // AFI=1  SAFI=1
  bool mp_ipv6u;   // AFI=2  SAFI=1
  bool mp_vpnv4;   // AFI=1  SAFI=128
  bool mp_evpn;    // AFI=25 SAFI=70
  bool mp_vpls;    // AFI=25 SAFI=65 (VPLS)

  // 4-byte ASN capability (RFC 6793)
  bool as4;
  uint32_t as4_value;

  // Graceful Restart (RFC 4724) (minimal)
  bool graceful_restart;
  uint16_t gr_time; // seconds (12-bit field from capability)

  // Route Refresh (RFC 2918)
  bool route_refresh;
} bgp_caps_t;

void caps_init(bgp_caps_t* c);
