#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
#include "bgp/attrs.h"

typedef struct {
  uint16_t afi;
  uint8_t  safi;

  uint8_t  nh_len;
  uint8_t  nh[32];

  const uint8_t* nlri;
  uint16_t nlri_len;
} mp_reach_t;

typedef struct {
  uint16_t afi;
  uint8_t  safi;

  const uint8_t* withdrawn;
  uint16_t withdrawn_len;
} mp_unreach_t;

// Returns UPDATE payload length (excluding 19-byte BGP header) or -1.
int mp_update_encode(uint8_t* out, int outlen,
                     const bgp_attrs_t* attrs,
                     bool is_ebgp, uint32_t local_asn,
                     const mp_reach_t* reach,
                     const mp_unreach_t* unreach);
