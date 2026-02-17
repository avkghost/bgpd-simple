// src/bgp.c
#include "bgp/bgp.h"
#include "bgp/core.h"
#include "bgp/peer.h"
#include "bgp/fsm.h"
#include "bgp/event.h"
#include "bgp/log.h"
#include "bgp/msg.h"       /* peer_send_update4, peer_send_mp */
#include "bgp/afi_ipv4u.h" /* afi_ipv4u_advertise_peer */
#include "bgp/attrs.h"
#include "bgp/cli.h"       /* cli_start */
#include "bgp/nlri.h"      /* nlri_encode_vpnv4_one */
#include "bgp/update6.h"   /* update6_encode_reach */
#include "bgp/vrf.h"       /* vrf_db_t */
#include "bgp/extcomm.h"   /* for RT encoding */

#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>

struct bgp_global {
  event_loop_t* loop;
  bgp_core_t    core;

  bgp_peer_t* peers[64];
  int         peer_count;

  /* Locally-originated prefixes (from "network" stmts under router bgp). */
  bgp_network_t networks[256];
  int           network_count;

  /* VRF database — needed for VPNv4 RD/RT when advertising VRF networks. */
  vrf_db_t vrfs;
};

static bgp_peer_t* peer_alloc(event_loop_t* loop, bgp_core_t* core, struct in_addr addr){
  bgp_peer_t* p = (bgp_peer_t*)calloc(1, sizeof(*p));
  if(!p) return NULL;

  p->addr = addr;
  p->loop = loop;
  p->core = core;

  // I/O init
  p->fd = -1;
  p->rxlen = 0;

  // FSM init sets state/timers to safe defaults
  bgp_fsm_init(p);

  // Hook classic UPDATE sender used via function pointer in core/rib
  p->send_update4 = peer_send_update4;

  return p;
}

static void peer_free(bgp_peer_t* p){
  if(!p) return;

  if(p->fd >= 0){
    /* Deregister before close so the event loop does not fire stale callbacks. */
    (void)ev_del_fd(p->loop, p->fd);
    close(p->fd);
    p->fd = -1;
  }
  free(p);
}

static void peer_start_session(bgp_peer_t* p){
  if(!p) return;
  bgp_fsm_event(p, BGP_EVT_START);
}

bgp_global_t* bgp_create(void){
  bgp_global_t* g = (bgp_global_t*)calloc(1, sizeof(*g));
  if(!g) return NULL;

  g->loop = ev_create();
  if(!g->loop){
    free(g);
    return NULL;
  }

  core_init(&g->core);
  g->peer_count    = 0;
  g->network_count = 0;
  return g;
}

void bgp_destroy(bgp_global_t* g){
  if(!g) return;

  /* Tear down CLI before closing the event loop so ev_del_fd works. */
  cli_stop();

  for(int i = 0; i < g->peer_count; i++){
    peer_free(g->peers[i]);
    g->peers[i] = NULL;
  }
  g->peer_count = 0;

  if(g->loop){
    ev_destroy(g->loop);
    g->loop = NULL;
  }

  core_destroy(&g->core);

  free(g);
}

/**
 * @brief Advertise globally-scoped IPv4 unicast "network" prefixes to a peer.
 */
static void advertise_networks_to_peer(bgp_global_t* g, bgp_peer_t* p)
{
  if(!g || !p || !p->send_update4) return;
  if(!p->af_ipv4u_active) return;

  bool is_ibgp = (p->local_asn == p->remote_asn_cfg);

  for(int i = 0; i < g->network_count; i++){
    /* Skip VRF networks — those are advertised as VPNv4 separately. */
    if(g->networks[i].vrf_name[0] != 0) continue;

    bgp_attrs_t a;
    attrs_init(&a);

    a.origin       = 0; /* IGP */
    a.has_next_hop = true;
    a.next_hop     = p->local_id;

    if(is_ibgp){
      a.has_local_pref = true;
      a.local_pref     = 100;
    }

    /* Apply outbound route-map (e.g. set local-preference, MED, community) */
    if(!route_map_apply(&g->core.pol, p->rmap_out,
                        g->networks[i].prefix, g->networks[i].plen, &a))
      continue;   /* route-map denied this prefix */

    (void)p->send_update4(p,
                          &g->networks[i].prefix,
                          g->networks[i].plen,
                          &a,
                          /*withdraw=*/false);
  }
}

/*
 * Encode a Route Target extended community (type 0x0002, ASN:NN format)
 * into an 8-byte buffer.
 */
static void rt_encode_asn(uint8_t out[8], uint16_t asn, uint32_t nn)
{
  out[0] = 0x00; out[1] = 0x02;   /* Type: RT, ASN-specific */
  out[2] = (uint8_t)(asn >> 8); out[3] = (uint8_t)asn;
  out[4] = (uint8_t)(nn >> 24); out[5] = (uint8_t)(nn >> 16);
  out[6] = (uint8_t)(nn >> 8);  out[7] = (uint8_t)nn;
}

/**
 * @brief Advertise VRF "network" prefixes as VPNv4 MP_REACH_NLRI to a peer.
 *
 * For each network statement inside `address-family ipv4 vrf <NAME>`, build
 * a VPNv4 NLRI (label + RD + prefix) and send it as MP_REACH (AFI=1 SAFI=128).
 * The Route Target is taken from the VRF's export_rts[].
 */
static void advertise_vpnv4_networks_to_peer(bgp_global_t* g, bgp_peer_t* p)
{
  if(!g || !p) return;
  if(!p->af_vpnv4_active || !p->caps.mp_vpnv4) return;

  bool is_ibgp = (p->local_asn == p->remote_asn_cfg);

  for(int i = 0; i < g->network_count; i++){
    const bgp_network_t* net = &g->networks[i];
    if(net->vrf_name[0] == 0) continue;  /* global network, not VPNv4 */

    /* Look up the VRF config for RD and export RTs */
    vrf_t* vrf = vrf_get(&g->vrfs, net->vrf_name, /*create=*/0);
    if(!vrf){
      log_msg(BGP_LOG_WARN, "VPNv4: VRF %s not found for network %s/%u",
              net->vrf_name, inet_ntoa(net->prefix), net->plen);
      continue;
    }
    if(vrf->rd.asn == 0 && vrf->rd.val == 0){
      log_msg(BGP_LOG_WARN, "VPNv4: VRF %s has no RD configured", vrf->name);
      continue;
    }

    /* Build the VPNv4 NLRI: derive label from RD NN (labels 0-15 reserved) */
    nlri_vpnv4_t nlri_entry;
    nlri_entry.label  = (vrf->rd.val >= 16) ? (vrf->rd.val & 0xFFFFF) : 100;
    nlri_entry.rd_asn = (uint16_t)vrf->rd.asn;
    nlri_entry.rd_val = vrf->rd.val;
    nlri_entry.pfx    = net->prefix;
    nlri_entry.plen   = net->plen;

    uint8_t nlri_buf[32];
    int nlri_len = nlri_encode_vpnv4_one(nlri_buf, (int)sizeof(nlri_buf),
                                          &nlri_entry);
    if(nlri_len < 0) continue;

    /* Build attrs with export RTs as extended communities */
    bgp_attrs_t a;
    attrs_init(&a);
    a.origin = 0;   /* IGP */
    if(!is_ibgp){
      a.has_as_path = true;
    }
    if(is_ibgp){
      a.has_local_pref = true;
      a.local_pref     = 100;
    }

    /* Attach export Route Targets */
    if(vrf->export_count > 0){
      a.has_ext_communities   = true;
      a.ext_community_count   = 0;
      for(int r = 0; r < vrf->export_count &&
                      a.ext_community_count < 32; r++){
        rt_encode_asn(a.ext_communities[a.ext_community_count],
                      (uint16_t)vrf->export_rts[r].asn,
                      vrf->export_rts[r].val);
        a.ext_community_count++;
      }
    }

    /* Next-hop for VPNv4 (AFI=1 SAFI=128): RFC 4364 §4.3.2 requires a
     * 12-byte next-hop: 8 zero bytes (the RD, set to all-zeros for the NH
     * field) followed by the 4-byte IPv4 address of the local router.
     * Sending only 4 bytes causes peers to send NOTIFICATION 3/9
     * (Optional Attribute Error) because nh_len=4 is invalid for SAFI 128. */
    uint8_t nh[12];
    memset(nh, 0, 8);                    /* 8-byte RD = all zeros */
    memcpy(nh + 8, &p->local_id, 4);    /* 4-byte IPv4 next-hop */

    /* Apply outbound route-map (e.g. set local-preference, MED, community) */
    if(!route_map_apply(&g->core.pol, p->rmap_out, net->prefix, net->plen, &a))
      continue;   /* route-map denied this VPNv4 prefix */

    log_msg(BGP_LOG_INFO, "VPNv4: advertising %s/%u in VRF %s to %s",
            inet_ntoa(net->prefix), net->plen, vrf->name, inet_ntoa(p->addr));

    (void)peer_send_mp(p, 1, 128, &a, nh, 12,
                       nlri_buf, (uint16_t)nlri_len, /*withdraw=*/false);
  }
}

/**
 * @brief Advertise locally-configured IPv6 unicast "network" prefixes.
 *
 * Currently the config does not have a separate IPv6 network list, so we
 * send a router-id-derived summary to signal reachability.  A full
 * implementation would require `address-family ipv6 unicast` network stmts.
 *
 * For now: if IPv6 is negotiated and the peer's link-local can be derived,
 * just signal the NLRI empty (no prefixes) to complete the MP negotiation.
 * Real IPv6 prefix advertisement is done via update6_encode_reach() when
 * IPv6 network statements are added to the config.
 */
static void advertise_ipv6_to_peer(bgp_global_t* g, bgp_peer_t* p)
{
  if(!g || !p) return;
  if(!p->af_ipv6u_active || !p->caps.mp_ipv6u) return;
  /* Placeholder: IPv6 unicast network statements are not yet in the config
   * parser.  Log the intent and return. */
  log_msg(BGP_LOG_INFO,
          "IPv6 unicast: no locally-configured prefixes to advertise to %s",
          inet_ntoa(p->addr));
}

int bgp_start(bgp_global_t* g, const bgp_config_t* cfg, bool daemonize){
  (void)daemonize; /* future: fork + setsid */

  if(!g || !cfg) return -1;

  /* ── 1. Core identifiers ─────────────────────────────────────────── */
  core_set_ids(&g->core, cfg->params.router_id, cfg->cluster_id);
  g->core.local_asn     = cfg->params.asn;
  g->core.rib.local_asn = cfg->params.asn;
  g->core.rib.router_id = cfg->params.router_id;

  /* ── 2. Policy database ──────────────────────────────────────────── */
  /*
   * Copy the policy_db parsed from the config file into core so that
   * decision.c (which references c->pol) can evaluate route-maps.
   * Both bgp_config_t.policy and bgp_core_t.pol are policy_db_t values;
   * they share the same heap-allocated plists/rmaps arrays — ownership
   * transfers to core here.  The config struct is ephemeral (stack in main).
   */
  g->core.pol = cfg->policy;

  /* ── 3. Locally-originated networks ─────────────────────────────── */
  int ncount = cfg->network_count;
  if(ncount > (int)(sizeof(g->networks)/sizeof(g->networks[0])))
    ncount = (int)(sizeof(g->networks)/sizeof(g->networks[0]));
  memcpy(g->networks, cfg->networks, (size_t)ncount * sizeof(g->networks[0]));
  g->network_count = ncount;

  /* ── 3b. VRF database (for VPNv4 RD/RT lookup) ──────────────────── */
  g->vrfs = cfg->vrfs;   /* struct copy — pointer ownership transfers */

  /* ── 3c. Populate core vrf_inst[] from config VRFs ──────────────── */
  /*
   * core_on_established() iterates c->vrf_inst[] to send EVPN IMET and VPLS
   * advertisements on peer bring-up.  The config VRFs are stored in g->vrfs
   * (used for VPNv4 RD/RT lookup), but core.c has its own vrf_inst array
   * which must be seeded here from the same source.
   */
  for(int i = 0; i < cfg->vrfs.vrf_count; i++){
    const vrf_t* cv = &cfg->vrfs.vrfs[i];
    vrf_instance_t* vi = core_get_vrf(&g->core, cv->name, /*create=*/1);
    if(vi){
      vi->cfg = *cv;  /* copy the full vrf_t config (name, RD, RTs, vni, bridge) */
    }
  }

  /* ── 4. Build peers from config ──────────────────────────────────── */
  for(int i = 0; i < cfg->neighbor_count; i++){
    const bgp_neighbor_cfg_t* nc = &cfg->neighbors[i];

    if(g->peer_count >= (int)(sizeof(g->peers)/sizeof(g->peers[0]))){
      log_msg(BGP_LOG_ERROR, "bgp_start: peer table full (max %d)",
              (int)(sizeof(g->peers)/sizeof(g->peers[0])));
      return -1;
    }

    bgp_peer_t* p = peer_alloc(g->loop, &g->core, nc->addr);
    if(!p) return -1;

    p->remote_asn_cfg  = nc->remote_asn;
    strncpy(p->description, nc->description, sizeof(p->description)-1);

    p->local_asn       = cfg->params.asn;
    p->local_id        = cfg->params.router_id;
    p->local_hold      = nc->hold_time ? nc->hold_time : cfg->params.hold_time;
    p->local_keepalive = nc->keepalive ? nc->keepalive : cfg->params.keepalive;

    strncpy(p->rmap_in,  nc->rmap_in,  sizeof(p->rmap_in)-1);
    strncpy(p->rmap_out, nc->rmap_out, sizeof(p->rmap_out)-1);

    p->is_rr_client    = nc->is_rr_client;
    p->af_ipv4u_active = nc->af_ipv4u_active;
    p->af_ipv6u_active = nc->af_ipv6u_active;
    p->af_vpnv4_active = nc->af_vpnv4_active;
    p->af_evpn_active  = nc->af_evpn_active;
    p->af_vpls_active  = nc->af_vpls_active;

    g->peers[g->peer_count++] = p;
    core_register_peer(&g->core, p);
  }

  /* ── 5. Register the established callback ───────────────────────── */
  g->core.on_established_cb = (void(*)(void*, bgp_peer_t*))bgp_on_peer_established;
  g->core.on_established_ud = g;

  /* ── 6. Passive TCP listen ───────────────────────────────────────── */
  if(core_start_listen(&g->core, g->loop, BGP_PORT) < 0){
    log_msg(BGP_LOG_WARN,
            "bgp_start: passive TCP listen on port %u failed — continuing",
            BGP_PORT);
    /* Non-fatal: outbound (active) sessions still work. */
  }

  /* ── 7. VTY CLI ──────────────────────────────────────────────────── */
  if(cli_start(&g->core, g->loop, "/var/run/bgpd.sock") < 0){
    log_msg(BGP_LOG_WARN, "bgp_start: VTY CLI start failed — continuing");
    /* Non-fatal: daemon operates normally without CLI. */
  }

  /* ── 8. Start outbound sessions ──────────────────────────────────── */
  for(int i = 0; i < g->peer_count; i++){
    peer_start_session(g->peers[i]);
  }

  return 0;
}

int bgp_run(bgp_global_t* g){
  if(!g || !g->loop) return -1;
  return ev_run(g->loop);
}

void bgp_stop(bgp_global_t* g){
  if(!g || !g->loop) return;
  ev_stop(g->loop);
}

/**
 * @brief Called by core_on_established() to advertise locally-configured
 *        networks and the full IPv4 unicast RIB to a newly-established peer.
 *
 * This is the bridge between the protocol layer (core/fsm) and the
 * application-level initial advertisement.  Separated from core.c so that
 * core.c does not need to know about the bgp_global_t network list.
 *
 * @note The caller (core_on_established) already logs "BGP Established".
 */
void bgp_on_peer_established(bgp_global_t* g, bgp_peer_t* p)
{
  if(!g || !p) return;

  /* ── IPv4 unicast ──────────────────────────────────────────────── */
  if(p->af_ipv4u_active){
    advertise_networks_to_peer(g, p);       /* locally-originated globals */
    afi_ipv4u_advertise_peer(&g->core, p);  /* full IPv4 RIB */
  }

  /* ── VPNv4 (VRF network statements) ───────────────────────────── */
  advertise_vpnv4_networks_to_peer(g, p);

  /* ── IPv6 unicast ──────────────────────────────────────────────── */
  advertise_ipv6_to_peer(g, p);
}
