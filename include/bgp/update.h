#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
#include "bgp/attrs.h"

typedef struct {
  struct in_addr pfx;
  uint8_t plen;
} bgp_prefix4_t;

typedef struct {
  // Withdrawn
  bgp_prefix4_t withdrawn[256];
  int withdrawn_count;

  // Path attributes
  bgp_attrs_t attrs;

  // NLRI
  bgp_prefix4_t nlri[256];
  int nlri_count;
} bgp_update4_t;

void update4_init(bgp_update4_t* u);
int  update4_decode(bgp_update4_t* u, const uint8_t* msg, int msglen, bool is_ebgp);
int  update4_encode(uint8_t* out, int outlen, const bgp_update4_t* u, bool include_local_pref);
