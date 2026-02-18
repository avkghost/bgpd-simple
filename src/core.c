// src/core.c
#include "bgp/core.h"
#include "bgp/event.h"
#include "bgp/sock.h"
#include "bgp/fsm.h"
#include "bgp/decision.h"
#include "bgp/peer.h"
#include "bgp/log.h"
#include "bgp/evpn.h"
#include "bgp/vpls.h"
#include "bgp/vpn.h"
#include "bgp/msg.h"
#include "bgp/nlri.h"
#include "bgp/rib6.h"
#include "bgp/netlink.h"

#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stddef.h>

void core_init(bgp_core_t* c){
  memset(c, 0, sizeof(*c));
  rib4_init(&c->rib);
  rib6_init(&c->rib6, 0, (struct in6_addr){0});
  c->listen_fd = -1;
}

void core_destroy(bgp_core_t* c){
  if(!c) return;
  rib4_destroy(&c->rib);
  rib6_destroy(&c->rib6);
  policy_destroy(&c->pol);
  for(int i = 0; i < c->vrf_inst_count; i++){
    rib4_destroy(&c->vrf_inst[i].rib4);
  }
  free(c->vrf_inst);
  c->vrf_inst = NULL;
  c->vrf_inst_count = c->vrf_inst_cap = 0;
}

void core_set_ids(bgp_core_t* c, struct in_addr router_id, struct in_addr cluster_id){
  c->router_id  = router_id;
  c->cluster_id = cluster_id;
}

void core_set_fib_table(bgp_core_t* c, int table){
  c->fib_table = table;
}

void core_register_peer(bgp_core_t* c, bgp_peer_t* p){
  if(c->peer_count < (int)(sizeof(c->peers)/sizeof(c->peers[0]))){
    c->peers[c->peer_count++] = p;
  }
}

vrf_instance_t* core_get_vrf(bgp_core_t* c, const char* name, int create){
  for(int i=0;i<c->vrf_inst_count;i++){
    if(strcmp(c->vrf_inst[i].cfg.name, name) == 0) return &c->vrf_inst[i];
  }
  if(!create) return NULL;

  if(c->vrf_inst_count == c->vrf_inst_cap){
    int ncap = (c->vrf_inst_cap == 0) ? 8 : c->vrf_inst_cap * 2;
    vrf_instance_t* n = (vrf_instance_t*)realloc(c->vrf_inst, (size_t)ncap * sizeof(vrf_instance_t));
    if(!n) return NULL;
    c->vrf_inst = n;
    c->vrf_inst_cap = ncap;
  }

  vrf_instance_t* v = &c->vrf_inst[c->vrf_inst_count++];
  memset(v, 0, sizeof(*v));
  strncpy(v->cfg.name, name, sizeof(v->cfg.name)-1);
  v->cfg.name[sizeof(v->cfg.name)-1] = 0;
  rib4_init(&v->rib4);
  return v;
}


void core_on_peer_down(bgp_core_t* c, bgp_peer_t* p){
  if(!c || !p) return;
  log_msg(BGP_LOG_INFO, "core_on_peer_down: withdrawing all routes from %s",
          inet_ntoa(p->addr));

  /* Walk the global IPv4 RIB and remove every path that came from this peer */
  for(int i = 0; i < c->rib.entry_count; i++){
    rib_entry4_t* re = &c->rib.entries[i];
    for(int j = 0; j < re->path_count;){
      if(re->paths[j].from == p){
        memmove(&re->paths[j], &re->paths[j+1],
                (size_t)(re->path_count - j - 1) * sizeof(re->paths[0]));
        re->path_count--;
        continue;
      }
      j++;
    }
    (void)rib4_recompute_best(&c->rib, i);
  }

  /* Walk the global IPv6 RIB and remove every path that came from this peer */
  for(int i = 0; i < c->rib6.entry_count; i++){
    rib_entry6_t* re = &c->rib6.entries[i];
    for(int j = 0; j < re->path_count;){
      if(re->paths[j].from == p){
        memmove(&re->paths[j], &re->paths[j+1],
                (size_t)(re->path_count - j - 1) * sizeof(re->paths[0]));
        re->path_count--;
        continue;
      }
      j++;
    }
    rib6_recompute_best(&c->rib6, i);
  }

  /* Also purge from per-VRF RIBs */
  for(int v = 0; v < c->vrf_inst_count; v++){
    rib4_t* vrib = &c->vrf_inst[v].rib4;
    for(int i = 0; i < vrib->entry_count; i++){
      rib_entry4_t* re = &vrib->entries[i];
      for(int j = 0; j < re->path_count;){
        if(re->paths[j].from == p){
          memmove(&re->paths[j], &re->paths[j+1],
                  (size_t)(re->path_count - j - 1) * sizeof(re->paths[0]));
          re->path_count--;
          continue;
        }
        j++;
      }
      (void)rib4_recompute_best(vrib, i);
    }
  }
}


/* ---- Passive TCP listen ---- */

static void on_accept(int fd, uint32_t events, void* arg){
  bgp_core_t* c = (bgp_core_t*)arg;
  (void)events;

  struct sockaddr_in sa;
  socklen_t slen = sizeof(sa);
  int cfd = accept(fd, (struct sockaddr*)&sa, &slen);
  if(cfd < 0) return;

  /* Find a configured peer matching the source address */
  bgp_peer_t* peer = NULL;
  for(int i = 0; i < c->peer_count; i++){
    if(c->peers[i]->addr.s_addr == sa.sin_addr.s_addr){
      peer = c->peers[i];
      break;
    }
  }

  if(!peer){
    log_msg(BGP_LOG_WARN, "Passive TCP from unconfigured peer %s — rejected",
            inet_ntoa(sa.sin_addr));
    close(cfd);
    return;
  }

  bgp_fsm_accept(peer, cfd);
}

int core_start_listen(bgp_core_t* c, event_loop_t* loop, uint16_t port){
  if(!c || !loop) return -1;

  int lfd = sock_create_listen(port);
  if(lfd < 0){
    log_msg(BGP_LOG_ERROR, "core_start_listen: sock_create_listen(%u) failed", port);
    return -1;
  }

  if(ev_add_fd(loop, lfd, EV_READ, on_accept, c) < 0){
    close(lfd);
    return -1;
  }

  c->listen_fd = lfd;
  c->loop = loop;
  log_msg(BGP_LOG_INFO, "Listening for BGP connections on port %u", port);
  return 0;
}

void core_on_update4(bgp_core_t* c, bgp_peer_t* from, const bgp_update4_t* up){
  /* Delegate full decision process (policy, RIB, FIB, export) to decision module. */
  decision_on_update4(c, from, up);
}

void core_on_update6(bgp_core_t* c, bgp_peer_t* from, const bgp_update6_t* up){
  /* Delegate full IPv6 decision process (policy, RIB, FIB, export) to decision module. */
  decision_on_update6(c, from, up);
}

void core_on_evpn_update(bgp_core_t* c, bgp_peer_t* from,
                         const uint8_t* raw_attrs, int raw_attrs_len)
{
  if(!c || !from) return;

  const uint8_t *reach_nlri   = NULL; int reach_len   = 0;
  const uint8_t *unreach_nlri = NULL; int unreach_len = 0;

  if (raw_attrs && raw_attrs_len > 0) {
    evpn_extract_nlri_blobs(&reach_nlri, &reach_len,
                            &unreach_nlri, &unreach_len,
                            raw_attrs, raw_attrs_len);
  }

  /* Decode announced EVPN routes */
  if (reach_nlri && reach_len > 0) {
    int off = 0;
    while (off < reach_len) {
      evpn_route_t r;
      int used = evpn_nlri_decode_one(&r, reach_nlri + off, reach_len - off);
      if (used < 0) break;
      log_msg(BGP_LOG_INFO,
              "EVPN RX ANNOUNCE type=%u from %s rd=%u:%u eth_tag=%u",
              (unsigned)r.route_type, inet_ntoa(from->addr),
              (unsigned)r.rd_asn, (unsigned)r.rd_val, (unsigned)r.eth_tag);
      off += used;
    }
  }

  /* Decode withdrawn EVPN routes */
  if (unreach_nlri && unreach_len > 0) {
    int off = 0;
    while (off < unreach_len) {
      evpn_route_t r;
      int used = evpn_nlri_decode_one(&r, unreach_nlri + off, unreach_len - off);
      if (used < 0) break;
      log_msg(BGP_LOG_INFO,
              "EVPN RX WITHDRAW type=%u from %s rd=%u:%u",
              (unsigned)r.route_type, inet_ntoa(from->addr),
              (unsigned)r.rd_asn, (unsigned)r.rd_val);
      off += used;
    }
  }

  if (!reach_nlri && !unreach_nlri) {
    log_msg(BGP_LOG_INFO, "EVPN UPDATE from %s: no NLRI blobs extracted",
            inet_ntoa(from->addr));
  }
}

/* ── VPLS NLRI decode helper ─────────────────────────────────────────────── */

/*
 * RFC 4761 §3.2.2 VPLS NLRI format (19 bytes total):
 *   Length(2)=17 octets | RD(8) | VE-ID(2) | VE-Block-Offset(2) |
 *   VE-Block-Size(2) | Label-Base(3)
 * The 2-byte length field holds the octet-count of the value (17 bytes).
 */
typedef struct {
  uint16_t rd_asn;
  uint32_t rd_val;
  uint16_t ve_id;
  uint16_t ve_block_offset;
  uint16_t ve_block_size;
  uint32_t label;
} vpls_nlri_entry_t;

static int vpls_nlri_decode_one(vpls_nlri_entry_t* out,
                                const uint8_t* buf, int len)
{
  /* 2-byte length + 17 bytes of value = 19 bytes minimum */
  if (!out || !buf || len < 19) return -1;

  /* 2-byte length field (in octets per RFC 4761 §3.2.2) */
  uint16_t bytes = (uint16_t)((buf[0]<<8)|buf[1]);
  if (bytes != 17) return -1;      /* only 17-octet value supported */
  if (2 + (int)bytes > len) return -1;

  const uint8_t* p = buf + 2;
  /* RD type 0: 0x0000(2) + asn(2) + nn(4) */
  out->rd_asn = (uint16_t)((p[2]<<8)|p[3]);
  out->rd_val = ((uint32_t)p[4]<<24)|((uint32_t)p[5]<<16)|
                ((uint32_t)p[6]<<8)| p[7];
  p += 8;
  out->ve_id          = (uint16_t)((p[0]<<8)|p[1]); p += 2;
  out->ve_block_offset= (uint16_t)((p[0]<<8)|p[1]); p += 2;
  out->ve_block_size  = (uint16_t)((p[0]<<8)|p[1]); p += 2;
  /* Label-Base: 20-bit label in top bits, BoS in bit 0 of byte 2 */
  out->label = ((uint32_t)p[0]<<12)|((uint32_t)p[1]<<4)|(p[2]>>4);
  return 2 + bytes;   /* 19 bytes total */
}

void core_on_vpls_update(bgp_core_t* c, bgp_peer_t* from,
                         const uint8_t* raw_attrs, int raw_attrs_len)
{
  if(!c || !from) return;

  /* Extract VPLS NLRI from MP_REACH / MP_UNREACH (AFI=25 SAFI=65) */
  const uint8_t *reach_nlri   = NULL; int reach_len   = 0;
  const uint8_t *unreach_nlri = NULL; int unreach_len = 0;

  if (raw_attrs && raw_attrs_len > 0) {
    /* Walk attrs for AFI=25 SAFI=65 */
    int off = 0;
    while (off < raw_attrs_len) {
      if (off + 2 > raw_attrs_len) break;
      uint8_t flags = raw_attrs[off];
      uint8_t code  = raw_attrs[off+1];
      off += 2;
      bool extlen = (flags & 0x10) != 0;
      int  vlen   = 0;
      if (extlen) {
        if (off + 2 > raw_attrs_len) break;
        vlen  = (raw_attrs[off]<<8)|raw_attrs[off+1];
        off  += 2;
      } else {
        if (off + 1 > raw_attrs_len) break;
        vlen  = raw_attrs[off++];
      }
      if (off + vlen > raw_attrs_len) break;
      const uint8_t *v = raw_attrs + off;

      if (code == 14 && vlen >= 4) {
        uint16_t afi  = (uint16_t)((v[0]<<8)|v[1]);
        uint8_t  safi = v[2];
        if (afi == 25 && safi == 65) {
          int p = 3;
          if (p < vlen) {
            uint8_t nhlen = v[p++]; p += nhlen;
            if (p < vlen) {
              uint8_t snpa = v[p++];
              for (int s = 0; s < (int)snpa; s++) {
                if (p >= vlen) { p = vlen; break; }
                uint8_t slen = v[p++]; p += (slen+1)/2;
              }
              if (p < vlen) { reach_nlri = v+p; reach_len = vlen-p; }
            }
          }
        }
      } else if (code == 15 && vlen >= 3) {
        uint16_t afi  = (uint16_t)((v[0]<<8)|v[1]);
        uint8_t  safi = v[2];
        if (afi == 25 && safi == 65 && vlen > 3) {
          unreach_nlri = v+3; unreach_len = vlen-3;
        }
      }
      off += vlen;
    }
  }

  if (reach_nlri && reach_len > 0) {
    int off = 0;
    while (off < reach_len) {
      vpls_nlri_entry_t e;
      int used = vpls_nlri_decode_one(&e, reach_nlri + off, reach_len - off);
      if (used < 0) break;
      log_msg(BGP_LOG_INFO,
              "VPLS RX ANNOUNCE from %s rd=%u:%u ve-id=%u label=%u",
              inet_ntoa(from->addr),
              (unsigned)e.rd_asn, (unsigned)e.rd_val,
              (unsigned)e.ve_id,  (unsigned)e.label);
      off += used;
    }
  }

  if (unreach_nlri && unreach_len > 0) {
    int off = 0;
    while (off < unreach_len) {
      vpls_nlri_entry_t e;
      int used = vpls_nlri_decode_one(&e, unreach_nlri + off, unreach_len - off);
      if (used < 0) break;
      log_msg(BGP_LOG_INFO,
              "VPLS RX WITHDRAW from %s rd=%u:%u ve-id=%u",
              inet_ntoa(from->addr),
              (unsigned)e.rd_asn, (unsigned)e.rd_val,
              (unsigned)e.ve_id);
      off += used;
    }
  }

  if (!reach_nlri && !unreach_nlri) {
    log_msg(BGP_LOG_INFO, "VPLS UPDATE from %s: no NLRI blobs extracted",
            inet_ntoa(from->addr));
  }
}

/* ---- EVPN/VPLS advertise helpers ---- */

static int vrf_has_valid_rd(const vrf_t* v){
  return v && v->rd.asn != 0 && v->rd.val != 0;
}

static void send_evpn_imet(bgp_peer_t* p, const vrf_t* v){
  if(!p || !v) return;
  if(v->vni == 0) return;

  if(!vrf_has_valid_rd(v)){
    log_msg(BGP_LOG_WARN, "EVPN: VRF %s missing RD, skipping IMET", v->name);
    return;
  }

  uint8_t nlri[256];
  int n = evpn_nlri_type3_imet(nlri, (int)sizeof(nlri),
                              (uint16_t)v->rd.asn, (uint32_t)v->rd.val,
                              (uint32_t)v->vni,
                              p->local_id);
  if(n <= 0) return;

  uint8_t nh[4];
  memcpy(nh, &p->local_id, 4); // lab next-hop = router-id

  (void)peer_send_mp(p, 25, 70, NULL, nh, 4, nlri, (uint16_t)n, false);
}

static void send_evpn_type5_prefix(bgp_peer_t* p, const vrf_t* v,
                                   const struct in_addr* pfx, uint8_t plen){
  if(!p || !v || !pfx) return;
  if(v->vni == 0) return;

  if(!vrf_has_valid_rd(v)){
    log_msg(BGP_LOG_WARN, "EVPN: VRF %s missing RD, skipping RT5", v->name);
    return;
  }

  uint8_t nlri[256];
  struct in_addr gw = p->local_id; // lab gateway IP = router-id

  int n = evpn_nlri_type5_ip_prefix(nlri, (int)sizeof(nlri),
                                   (uint16_t)v->rd.asn, (uint32_t)v->rd.val,
                                   (uint32_t)v->vni,
                                   pfx, plen,
                                   gw);
  if(n <= 0) return;

  uint8_t nh[4];
  memcpy(nh, &p->local_id, 4);

  (void)peer_send_mp(p, 25, 70, NULL, nh, 4, nlri, (uint16_t)n, false);
}

static void send_vpls_min(bgp_peer_t* p, const vrf_t* v){
  if(!p || !v) return;

  // convention: VRF with bridge and no vni -> treat as VPLS service (lab)
  if(v->bridge[0] == 0) return;
  if(v->vni != 0) return;

  if(!vrf_has_valid_rd(v)){
    log_msg(BGP_LOG_WARN, "VPLS: VRF %s missing RD, skipping", v->name);
    return;
  }

  uint8_t nlri[64];
  const uint16_t ve_id = 1;

  /* Derive a valid label-base from the RD's NN value.
   * Labels 0-15 are reserved (RFC 3032); use NN if ≥ 16, else 100. */
  uint32_t label_base = (v->rd.val >= 16) ? (v->rd.val & 0xFFFFF) : 100;

  int n = vpls_nlri_min(nlri, (int)sizeof(nlri),
                        (uint16_t)v->rd.asn, (uint32_t)v->rd.val,
                        ve_id, label_base);
  if(n <= 0) return;

  uint8_t nh[4];
  memcpy(nh, &p->local_id, 4);

  /*
   * RFC 4761 §3.2.3: BGP speaker MUST include a Route Target (RT) extended
   * community in every VPLS BGP UPDATE so the receiver can identify which
   * VPLS instance the NLRI belongs to.  Encode each export RT as an
   * AS-specific RT extended community (type 0x00, sub-type 0x02, RFC 4360).
   * If no export RTs are configured, fall back to a single RT derived from
   * the VRF's RD (ASN:NN), which is the common convention.
   */
  bgp_attrs_t a;
  attrs_init(&a);
  a.origin = 0; /* IGP */
  a.has_ext_communities = true;
  a.ext_community_count = 0;

  if(v->export_count > 0){
    for(int r = 0; r < v->export_count &&
                   a.ext_community_count < 32; r++){
      uint8_t* ec = a.ext_communities[a.ext_community_count++];
      ec[0] = 0x00; ec[1] = 0x02;          /* type: AS-specific RT */
      ec[2] = (uint8_t)(v->export_rts[r].asn >> 8);
      ec[3] = (uint8_t)(v->export_rts[r].asn);
      ec[4] = (uint8_t)(v->export_rts[r].val >> 24);
      ec[5] = (uint8_t)(v->export_rts[r].val >> 16);
      ec[6] = (uint8_t)(v->export_rts[r].val >> 8);
      ec[7] = (uint8_t)(v->export_rts[r].val);
    }
  } else {
    /* Fallback: derive RT from RD (ASN:NN) */
    uint8_t* ec = a.ext_communities[a.ext_community_count++];
    ec[0] = 0x00; ec[1] = 0x02;
    ec[2] = (uint8_t)(v->rd.asn >> 8);
    ec[3] = (uint8_t)(v->rd.asn);
    ec[4] = (uint8_t)(v->rd.val >> 24);
    ec[5] = (uint8_t)(v->rd.val >> 16);
    ec[6] = (uint8_t)(v->rd.val >> 8);
    ec[7] = (uint8_t)(v->rd.val);
  }

  (void)peer_send_mp(p, 25, 65, &a, nh, 4, nlri, (uint16_t)n, false);
}

void core_on_established(bgp_core_t* c, bgp_peer_t* p){
  if(!c || !p) return;

  /* EVPN: advertise IMET for each VNI-bearing VRF */
  if(p->af_evpn_active && p->caps.mp_evpn){
    for(int i=0;i<c->vrf_inst_count;i++){
      vrf_instance_t* vi = &c->vrf_inst[i];
      if(vi->cfg.vni != 0){
        log_msg(BGP_LOG_INFO, "EVPN: advertising IMET for VRF %s vni=%u to %s",
                vi->cfg.name, vi->cfg.vni, inet_ntoa(p->addr));
        send_evpn_imet(p, &vi->cfg);
      }
    }
  }

  /* VPLS: advertise minimal NLRI for bridge-backed VRFs */
  if(p->af_vpls_active && p->caps.mp_vpls){
    for(int i=0;i<c->vrf_inst_count;i++){
      vrf_instance_t* vi = &c->vrf_inst[i];
      if(vi->cfg.bridge[0] && vi->cfg.vni == 0){
        log_msg(BGP_LOG_INFO, "VPLS: advertising service for VRF %s (bridge=%s) to %s",
                vi->cfg.name, vi->cfg.bridge, inet_ntoa(p->addr));
        send_vpls_min(p, &vi->cfg);
      }
    }
  }

  /*
   * Advertise locally-originated networks and the current best-path RIB.
   * Delegated to the application layer via a callback so that core.c does
   * not need to know about bgp_global_t or the network list.
   */
  if(c->on_established_cb){
    c->on_established_cb(c->on_established_ud, p);
  }
}

/*
 * Called by main after Established to advertise configured IPv4 networks as EVPN RT5 into all VNI VRFs.
 * This is gated by (af_evpn_active && negotiated mp_evpn).
 */
void core_advertise_evpn_type5_for_networks(bgp_core_t* c, bgp_peer_t* p,
                                           const struct in_addr* pfx, uint8_t plen)
{
  if(!c || !p || !pfx) return;
  if(!(p->af_evpn_active && p->caps.mp_evpn)) return;

  for(int i=0;i<c->vrf_inst_count;i++){
    vrf_instance_t* vi = &c->vrf_inst[i];
    if(vi->cfg.vni == 0) continue;

    log_msg(BGP_LOG_INFO, "EVPN: advertising RT5 %s/%u into VRF %s vni=%u to %s",
            inet_ntoa(*pfx), plen, vi->cfg.name, vi->cfg.vni, inet_ntoa(p->addr));

    send_evpn_type5_prefix(p, &vi->cfg, pfx, plen);
  }
}
