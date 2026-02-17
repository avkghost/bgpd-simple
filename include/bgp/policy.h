#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
#include "bgp/attrs.h"

typedef struct {
  char name[64];
  int seq;
  bool permit;
  struct in_addr pfx;
  uint8_t plen;
  uint8_t ge; // 0 means unset
  uint8_t le; // 0 means unset
} prefix_list_rule_t;

typedef struct {
  char name[64];
  prefix_list_rule_t rules[256];
  int rule_count;
} prefix_list_t;

typedef struct {
  char name[64];
  int seq;
  bool permit;

  /* ── match conditions ─────────────────────────────────────────────── */
  char match_plist[64];       /* match ip address prefix-list NAME      */
  char match_community[64];   /* match community NAME (list name)        */

  /* ── set actions ─────────────────────────────────────────────────── */
  bool     set_local_pref;
  uint32_t local_pref;

  bool     set_med;
  uint32_t med;

  bool     set_next_hop_self; /* set ip next-hop self                    */

  bool     set_community;
  uint32_t community[32];
  int      community_count;
  bool     community_additive; /* set community ... additive             */

  bool     set_as_path_prepend;
  uint32_t prepend_asn;
  int      prepend_count;     /* how many times to prepend               */
} route_map_entry_t;

typedef struct {
  char name[64];
  route_map_entry_t ents[128];
  int ent_count;
} route_map_t;

typedef struct {
  prefix_list_t* plists;  // heap-allocated
  int plist_count;
  int plist_cap;

  route_map_t* rmaps;  // heap-allocated
  int rmap_count;
  int rmap_cap;
} policy_db_t;

void policy_init(policy_db_t* p);
void policy_destroy(policy_db_t* p);

prefix_list_t* policy_get_plist(policy_db_t* db, const char* name, bool create);
route_map_t*   policy_get_rmap(policy_db_t* db, const char* name, bool create);

bool prefix_list_permit(const prefix_list_t* pl, struct in_addr pfx, uint8_t plen);

bool route_map_apply(const policy_db_t* db, const char* rmap_name,
                     struct in_addr pfx, uint8_t plen,
                     bgp_attrs_t* attrs /* in/out */);
