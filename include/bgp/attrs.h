#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>

/** Maximum number of AS numbers stored in the full AS_PATH. */
#define AS_PATH_MAX 256

typedef struct {
  // Mandatory/basic
  uint8_t origin;            // 0 IGP, 1 EGP, 2 INCOMPLETE

  bool has_as_path;
  uint32_t as_path_first;    // first ASN (convenience for eBGP check)
  uint32_t as_path[AS_PATH_MAX]; // full ordered list (AS_SEQUENCE segments expanded)
  int      as_path_len;      // number of valid entries in as_path[]

  /* RFC 4893: AS4_PATH attribute (code 17) for 4-octet ASN support */
  bool has_as4_path;
  uint32_t as4_path[AS_PATH_MAX]; // 4-octet ASN values from AS4_PATH attribute
  int      as4_path_len;      // number of valid entries in as4_path[]

  bool has_next_hop;
  struct in_addr next_hop;

  // Common discretionary
  bool has_med;
  uint32_t med;

  bool has_local_pref;
  uint32_t local_pref;

  bool has_community;
  uint32_t community[32];
  int community_count;

  // RR attributes
  bool has_originator_id;
  struct in_addr originator_id;

  bool has_cluster_list;
  struct in_addr cluster_list[32];
  int cluster_count;

  // Extended Communities (attr code 16) — carries Route Targets for EVPN/VPNv4/VPLS.
  // Each entry is 8 raw bytes in wire order.
  bool has_ext_communities;
  uint8_t ext_communities[32][8];
  int ext_community_count;

  /* Policy transient: set by route_map_apply, consumed by export code */
  bool set_next_hop_self;

} bgp_attrs_t;

void attrs_init(bgp_attrs_t* a);
int  attrs_decode(bgp_attrs_t* a, const uint8_t* p, int len, bool is_ebgp);
int  attrs_encode(uint8_t* out, int outlen, const bgp_attrs_t* a, bool include_local_pref, bool as4_capable);
