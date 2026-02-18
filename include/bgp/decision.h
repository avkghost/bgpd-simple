/**
 * @file decision.h
 * @brief BGP decision process: best-path selection, FIB programming, and
 *        route export to peers (Adj-RIB-Out).
 *
 * The decision module owns:
 *  - Inbound route-map application (filter/modify on receipt).
 *  - Best-path selection (via rib4_recompute_best / rib6_recompute_best).
 *  - FIB programming via the netlink abstraction.
 *  - Route-reflector attribute injection (ORIGINATOR_ID, CLUSTER_LIST).
 *  - Outbound route-map application and export to peers.
 */
#pragma once
#include "bgp/core.h"
#include "bgp/update.h"
#include "bgp/update6.h"

typedef struct bgp_peer bgp_peer_t;

/**
 * @brief Process a received IPv4 unicast UPDATE through the full decision pipe.
 *
 * Applies inbound policy, installs into Adj-RIB-In, recomputes best path,
 * programs the FIB, and exports to all eligible peers with outbound policy.
 *
 * @param c          Routing core (RIB + policy + peer list).
 * @param from       Peer that sent the UPDATE.
 * @param up         Decoded UPDATE (withdrawals + announcements).
 */
void decision_on_update4(bgp_core_t* c, bgp_peer_t* from,
                          const bgp_update4_t* up);

/**
 * @brief Process a received IPv6 unicast UPDATE through the full decision pipe.
 *
 * Parallel to decision_on_update4 but for IPv6 routes (rib6_t).
 * Applies inbound policy, installs into Adj-RIB-In, recomputes best path,
 * programs the FIB, and exports to all eligible peers with outbound policy.
 *
 * @param c          Routing core (RIB + policy + peer list).
 * @param from       Peer that sent the UPDATE.
 * @param up         Decoded IPv6 UPDATE (withdrawals + announcements).
 */
void decision_on_update6(bgp_core_t* c, bgp_peer_t* from,
                          const bgp_update6_t* up);
