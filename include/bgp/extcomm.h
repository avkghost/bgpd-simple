#pragma once
#include <stdint.h>
#include <stdbool.h>
#include "bgp/vrf.h"

#define EXTCOMM_MAX 64

typedef struct {
  // store only RT type ASN:NN (2-octet ASN in baseline)
  rt_asn_t rts[EXTCOMM_MAX];
  int rt_count;
} extcomm_set_t;

// Decode RTs from BGP Communities attribute "Extended Communities" (code 16),
// but in this baseline we’ll carry RTs via bgp_attrs_t as a set already.
// These helpers are used by VPN import/export logic.

bool rt_equal(rt_asn_t a, rt_asn_t b);
bool rt_set_has(const extcomm_set_t* s, rt_asn_t rt);
bool rt_sets_intersect(const extcomm_set_t* a, const rt_asn_t* b, int bcnt);
