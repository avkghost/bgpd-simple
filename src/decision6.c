/**
 * @file decision6.c
 * @brief BGP decision process for IPv6: best-path selection, FIB programming, and
 *        Adj-RIB-Out export with route-reflector support.
 *
 * Parallel to decision.c but for IPv6 unicast routes.
 */

#include "bgp/decision.h"
#include "bgp/core.h"
#include "bgp/peer.h"
#include "bgp/rib6.h"
#include "bgp/policy.h"
#include "bgp/attrs.h"
#include "bgp/netlink.h"
#include "bgp/log.h"

#include <arpa/inet.h>
#include <string.h>
#include <stdbool.h>

/* ---- FIB programming ---- */

/**
 * @brief Program the best path for @p e into the kernel FIB.
 *
 * Deletes the prefix if no best path exists; otherwise installs the
 * best next-hop via the netlink abstraction layer.
 */
static void fib_program_best_v6(bgp_core_t* c, rib_entry6_t* e)
{
  if (e->best_index < 0) {
    nl_route_delete_v6(e->pfx.pfx, e->pfx.plen, c->fib_table);
    return;
  }
  const rib_path6_t* best = &e->paths[e->best_index];
  nl_route_replace_v6(e->pfx.pfx, e->pfx.plen, best->next_hop, c->fib_table);
}

/* ---- Export eligibility (RFC 4456 route-reflector rules) ---- */

/**
 * @brief Return non-zero if a route from @p src should be exported to @p dst.
 *
 * RFC 4456 §2.2 reflection rules for an iBGP route reflector:
 *   - Never echo a route back to its originating peer.
 *   - Route from a client    → reflect to all clients + all non-clients.
 *   - Route from a non-client → reflect to clients only (non-client peers
 *     are assumed to be in a full mesh among themselves).
 *   - Route from an eBGP peer → send to all iBGP peers (clients and
 *     non-clients alike), same as a standard BGP speaker.
 *
 * "iBGP peer" here means local_asn == remote_asn_cfg (same AS).
 */
static int should_export_to(const bgp_peer_t* src, const bgp_peer_t* dst)
{
  if (dst == src) return 0;

  bool src_ibgp = (src->local_asn == src->remote_asn_cfg);
  bool dst_ibgp = (dst->local_asn == dst->remote_asn_cfg);

  /* eBGP source: normal export — send to every peer */
  if (!src_ibgp) return 1;

  /* iBGP source from a client: reflect to all peers */
  if (src->is_rr_client) return 1;

  /* iBGP source from a non-client: reflect only to clients.
   * Non-client peers are in a full iBGP mesh and receive the route
   * via that mesh directly; the RR must not reflect back to them. */
  return dst->is_rr_client || !dst_ibgp;
}

/* ---- Decision process entry point ---- */

void decision_on_update6(bgp_core_t* c, bgp_peer_t* from,
                         const bgp_update6_t* up)
{
  if (!c || !from || !up) return;

  /* --- Withdrawals --- */
  for (int i = 0; i < up->withdrawn_count; i++) {
    const struct in6_addr pfx = up->withdrawn[i].pfx;
    const uint8_t plen = up->withdrawn[i].plen;

    int ei = rib6_find_entry(&c->rib6, pfx, plen);
    rib6_withdraw(&c->rib6, from, pfx, plen);
    if (ei >= 0) {
      rib6_recompute_best(&c->rib6, ei);
      fib_program_best_v6(c, &c->rib6.entries[ei]);
    }

    /* Export withdrawals to eligible peers */
    for (int n = 0; n < c->peer_count; n++) {
      bgp_peer_t* dst = c->peers[n];
      if (!should_export_to(from, dst)) continue;
      if (dst->send_update6)
        dst->send_update6(dst, &pfx, plen, NULL, true);
    }
  }

  /* --- Announcements --- */
  for (int i = 0; i < up->nlri_count; i++) {
    const struct in6_addr pfx = up->nlri[i].pfx;
    const uint8_t plen = up->nlri[i].plen;

    bgp_attrs_t a = up->attrs;
    struct in6_addr next_hop = up->next_hop;

    /*
     * RFC 4456 §8 Loop prevention on inbound:
     *
     * 1. ORIGINATOR_ID: if the route carries our own router-id as the
     *    originator, we are the originator and must discard it.
     */
    if (c->cluster_id.s_addr != 0 &&
        a.has_originator_id &&
        a.originator_id.s_addr == c->router_id.s_addr) {
      char pfx_str[INET6_ADDRSTRLEN];
      inet_ntop(AF_INET6, &pfx, pfx_str, sizeof(pfx_str));
      char from_str[INET_ADDRSTRLEN];
      inet_ntop(AF_INET, &from->addr, from_str, sizeof(from_str));
      log_msg(BGP_LOG_DEBUG,
              "RR: discard %s/%u from %s: ORIGINATOR_ID is self",
              pfx_str, plen, from_str);
      continue;
    }

    /*
     * 2. CLUSTER_LIST: if the CLUSTER_LIST contains our cluster-id, the
     *    route has already been reflected through this cluster — discard.
     */
    if (c->cluster_id.s_addr != 0 && a.has_cluster_list) {
      bool loop = false;
      for (int ci = 0; ci < a.cluster_count; ci++) {
        if (a.cluster_list[ci].s_addr == c->cluster_id.s_addr) {
          loop = true;
          break;
        }
      }
      if (loop) {
        char pfx_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &pfx, pfx_str, sizeof(pfx_str));
        char from_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &from->addr, from_str, sizeof(from_str));
        log_msg(BGP_LOG_DEBUG,
                "RR: discard %s/%u from %s: own cluster-id in CLUSTER_LIST",
                pfx_str, plen, from_str);
        continue;
      }
    }

    /* Inbound policy — deny becomes implicit withdraw */
    if (!route_map_apply_v6(&c->pol, from->rmap_in, pfx, plen, &a)) {
      rib6_withdraw(&c->rib6, from, pfx, plen);
      char pfx_str[INET6_ADDRSTRLEN];
      inet_ntop(AF_INET6, &pfx, pfx_str, sizeof(pfx_str));
      log_msg(BGP_LOG_DEBUG, "decision6: inbound rmap '%s' denied %s/%u",
              from->rmap_in, pfx_str, plen);
      continue;
    }

    /* Add or update route in RIB */
    rib6_add_or_replace(&c->rib6, from, pfx, plen, &a, next_hop);

    int ei = rib6_find_entry(&c->rib6, pfx, plen);
    if (ei >= 0) {
      rib6_recompute_best(&c->rib6, ei);
      fib_program_best_v6(c, &c->rib6.entries[ei]);
    }

    /* Export to eligible peers with per-peer outbound policy */
    for (int n = 0; n < c->peer_count; n++) {
      bgp_peer_t* dst = c->peers[n];
      if (!should_export_to(from, dst)) continue;

      bgp_attrs_t outa = a;

      /*
       * RFC 4271 §6.3 AS_PATH modification:
       * When exporting to an eBGP peer, prepend the local ASN to the AS_PATH.
       * For iBGP, leave the AS_PATH unchanged (route-reflector will handle it).
       */
      bool to_ebgp = (dst->local_asn != dst->remote_asn_cfg);
      if (to_ebgp && outa.as_path_len < AS_PATH_MAX - 1) {
        /* Shift existing AS_PATH entries right and prepend local ASN */
        memmove(&outa.as_path[1], &outa.as_path[0],
                (size_t)outa.as_path_len * sizeof(outa.as_path[0]));
        outa.as_path[0] = dst->local_asn;
        outa.as_path_len++;
        outa.has_as_path = true;
      }

      /*
       * RFC 4456 §2.2 Route-reflector attribute injection:
       *
       * When reflecting an iBGP route, the RR MUST:
       *   a) Set ORIGINATOR_ID to the BGP ID of the route's original
       *      sender if not already present (never overwrite existing).
       *   b) Prepend own cluster-id to CLUSTER_LIST (always, even if
       *      CLUSTER_LIST is already present).
       *
       * Only apply when this router is acting as an RR
       * (cluster_id configured) and the source is an iBGP peer.
       */
      bool from_ibgp = (from->local_asn == from->remote_asn_cfg);
      if (c->cluster_id.s_addr != 0 && from_ibgp) {
        /* a) ORIGINATOR_ID — set only if not already present */
        if (!outa.has_originator_id) {
          outa.has_originator_id = true;
          outa.originator_id = from->remote_id; /* sender's BGP ID */
        }
        /* b) Prepend cluster-id to CLUSTER_LIST */
        if (outa.cluster_count < 32) {
          /* shift existing entries right and insert at front */
          memmove(&outa.cluster_list[1], &outa.cluster_list[0],
                  (size_t)outa.cluster_count * sizeof(outa.cluster_list[0]));
          outa.cluster_list[0] = c->cluster_id;
          outa.cluster_count++;
          outa.has_cluster_list = true;
        }
      }

      /* Outbound policy */
      if (!route_map_apply_v6(&c->pol, dst->rmap_out, pfx, plen, &outa))
        continue;

      /* Send UPDATE to peer with next-hop */
      if (dst->send_update6)
        dst->send_update6(dst, &pfx, plen, &outa, false);
    }
  }
}
