/*
 * IPv6 Routing Information Base (RIB) — parallel to rib4.h
 *
 * Stores IPv6 unicast routes received from BGP peers, performs
 * best-path selection per RFC 4271, and exports best paths for
 * installation in the kernel FIB and re-advertisement to peers.
 */

#pragma once

#include <netinet/in.h>
#include <stdint.h>
#include <stdbool.h>
#include "bgp/attrs.h"

/* Forward declarations */
typedef struct bgp_peer bgp_peer_t;

/* ── IPv6 Prefix ─────────────────────────────────────────────── */

typedef struct {
  struct in6_addr pfx;
  uint8_t plen;
} rib_prefix6_t;

/* ── IPv6 Path (single advertised route) ────────────────────── */

typedef struct {
  rib_prefix6_t pfx;
  bgp_peer_t* from;         /* originating peer, NULL = locally originated */
  bgp_attrs_t attrs;        /* path attributes (note: IPv4 nexthop unused) */
  struct in6_addr next_hop; /* IPv6-specific next-hop */
  uint32_t age_ms;          /* age since announcement */
} rib_path6_t;

/* ── IPv6 RIB Entry (one prefix, multiple paths) ────────────── */

typedef struct {
  rib_prefix6_t pfx;
  rib_path6_t* paths;       /* array of candidate paths */
  int path_count;           /* number of paths */
  int path_cap;             /* allocated capacity */
  int best_index;           /* index of selected best path, -1 if none */
} rib_entry6_t;

/* ── IPv6 RIB (entire routing table) ─────────────────────────── */

typedef struct {
  rib_entry6_t* entries;    /* array of prefixes */
  int entry_count;          /* number of entries */
  int entry_cap;            /* allocated capacity */
  uint32_t local_asn;       /* for comparison in best-path */
  struct in6_addr router_id; /* typically not used for IPv6 BGP */
} rib6_t;

/* ── Public API ───────────────────────────────────────────────── */

/**
 * Initialize an empty IPv6 RIB.
 */
void rib6_init(rib6_t* rib, uint32_t local_asn, struct in6_addr router_id);

/**
 * Destroy RIB and free all allocated memory.
 */
void rib6_destroy(rib6_t* rib);

/**
 * Find RIB entry for a given prefix.
 * Returns: index in rib->entries, or -1 if not found.
 */
int rib6_find_entry(const rib6_t* rib, struct in6_addr pfx, uint8_t plen);

/**
 * Withdraw all paths originated from a specific peer for a prefix.
 * If no paths remain, entry is left but path_count becomes 0.
 */
void rib6_withdraw(rib6_t* rib, bgp_peer_t* from,
                   struct in6_addr pfx, uint8_t plen);

/**
 * Add or replace a path in the RIB.
 * If entry doesn't exist, creates it.
 * If path from 'from' peer already exists for this prefix, replaces it.
 * Otherwise appends a new path.
 */
void rib6_add_or_replace(rib6_t* rib, bgp_peer_t* from,
                         struct in6_addr pfx, uint8_t plen,
                         const bgp_attrs_t* attrs,
                         struct in6_addr next_hop);

/**
 * Recompute the best path for a specific RIB entry.
 * Uses RFC 4271 best-path selection algorithm:
 *   1. Highest LOCAL_PREF
 *   2. Shortest AS_PATH
 *   3. Lowest ORIGIN
 *   4. Lowest MED (if same AS)
 *   5. eBGP > iBGP
 *   6. Lowest router-id (tie-breaker)
 *
 * Sets entry->best_index to the selected path, or -1 if no valid paths.
 */
void rib6_recompute_best(rib6_t* rib, int entry_idx);
