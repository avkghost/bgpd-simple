#pragma once
#include <stdint.h>
#include <netinet/in.h>
#include "bgp/vrf.h"
#include "bgp/attrs.h"
#include "bgp/extcomm.h"

typedef struct {
  // MPLS label (20-bit) + bottom-of-stack (we keep single label)
  uint32_t label; // 20-bit in high-level units

  // RD ASN:NN (baseline)
  rt_asn_t rd;

  // Prefix
  struct in_addr pfx;
  uint8_t plen;
} vpnv4_nlri_t;

typedef struct {
  vpnv4_nlri_t nlri[256];
  int nlri_count;

  vpnv4_nlri_t withdraw[256];
  int withdraw_count;

  // MP_REACH next hop
  struct in_addr nh;
  int has_nh;

  // Attributes (incl. RT set in attrs)
  bgp_attrs_t attrs;

  // Route Targets attached to the route (extracted from ext communities)
  extcomm_set_t rts;
} vpnv4_update_t;

void vpnv4_update_init(vpnv4_update_t* u);

// Parse UPDATE for MP_(UN)REACH only (attribute 14/15), leaving classic v4 NLRI to update4.c
int vpnv4_from_mp_attrs(vpnv4_update_t* out, const uint8_t* attrs, int attrs_len);
