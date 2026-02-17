#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
#include "bgp/attrs.h"

typedef struct bgp_peer bgp_peer_t;

typedef struct {
  struct in_addr pfx;
  uint8_t plen;
} rib_prefix4_t;

typedef struct {
  rib_prefix4_t pfx;
  bgp_peer_t* from;
  bgp_attrs_t attrs;
  uint32_t age_ms;
} rib_path4_t;

typedef struct {
  rib_prefix4_t pfx;
  rib_path4_t* paths;  // heap-allocated; cap tracked separately
  int path_count;
  int path_cap;

  int best_index; // -1 if none
} rib_entry4_t;

typedef struct {
  rib_entry4_t* entries;  // heap-allocated
  int entry_count;
  int entry_cap;

  /* local ASN, used by best-path to classify eBGP vs iBGP paths */
  uint32_t local_asn;
  /* local router-id for tie-breaking */
  struct in_addr router_id;
} rib4_t;

void rib4_init(rib4_t* r);
void rib4_init_with_local(rib4_t* r, uint32_t local_asn, struct in_addr router_id);
void rib4_destroy(rib4_t* r);

// Apply Adj-RIB-In changes (from UPDATE)
void rib4_withdraw(rib4_t* r, bgp_peer_t* from, struct in_addr pfx, uint8_t plen);
void rib4_add_or_replace(rib4_t* r, bgp_peer_t* from, struct in_addr pfx, uint8_t plen, const bgp_attrs_t* a);

// Decision process (best path select)
bool rib4_recompute_best(rib4_t* r, int entry_index);

// Export iterator
int  rib4_find_entry(rib4_t* r, struct in_addr pfx, uint8_t plen);
