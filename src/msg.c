// src/msg.c

#include "bgp/msg.h"
#include "bgp/log.h"
#include "bgp/fsm.h"
#include "bgp/update.h"
#include "bgp/core.h"
#include "bgp/peer.h"
#include "bgp/mpbgp.h"
#include "bgp/mp_update.h"
#include "bgp/vpn.h"

#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#define BGP_OPT_PARAM_CAPA 2
#define BGP_CAP_MP         1
#define BGP_CAP_RR         2
#define BGP_CAP_GR         64
#define BGP_CAP_AS4        65

static uint8_t* put_u16(uint8_t* p, uint16_t v){ *p++=(uint8_t)(v>>8); *p++=(uint8_t)v; return p; }
static uint8_t* put_u32(uint8_t* p, uint32_t v){ *p++=(uint8_t)(v>>24); *p++=(uint8_t)(v>>16); *p++=(uint8_t)(v>>8); *p++=(uint8_t)v; return p; }

static uint8_t* add_cap_mp(uint8_t* p, uint16_t afi, uint8_t safi){
  *p++ = BGP_CAP_MP;
  *p++ = 4;
  p = put_u16(p, afi);
  *p++ = 0;
  *p++ = safi;
  return p;
}

static uint8_t* add_cap_rr(uint8_t* p){
  *p++ = BGP_CAP_RR;
  *p++ = 0;
  return p;
}

static uint8_t* add_cap_as4(uint8_t* p, uint32_t asn){
  *p++ = BGP_CAP_AS4;
  *p++ = 4;
  p = put_u32(p, asn);
  return p;
}

static uint8_t* add_cap_gr(uint8_t* p, uint16_t restart_time){
  *p++ = BGP_CAP_GR;
  *p++ = 2;
  uint16_t rt = (restart_time & 0x0FFF);
  p = put_u16(p, rt);
  return p;
}

static int send_all(int fd, const void* buf, size_t len){
  const uint8_t* p = (const uint8_t*)buf;
  while(len){
    ssize_t n = send(fd, p, len, 0);
    if(n < 0){
      if(errno == EINTR) continue;
      if(errno == EAGAIN || errno == EWOULDBLOCK) return 0;
      return -1;
    }
    p += (size_t)n;
    len -= (size_t)n;
  }
  return 0;
}

static void fill_marker(uint8_t m[BGP_MARKER_LEN]){
  memset(m, 0xFF, BGP_MARKER_LEN);
}

static int parse_hdr(const uint8_t* b, size_t len, bgp_hdr_t* out){
  if(len < 19) return -1;
  memcpy(out, b, 19);
  for(int i=0;i<16;i++) if(out->marker[i] != 0xFF) return -1;
  out->len = ntohs(out->len);
  if(out->len < 19 || out->len > BGP_MAX_MSG) return -1;
  return 0;
}

static void parse_caps(bgp_peer_t* p, const uint8_t* caps, size_t len){
  size_t i = 0;
  while(i + 2 <= len){
    uint8_t code = caps[i++];
    uint8_t clen = caps[i++];
    if(i + clen > len) break;

    const uint8_t* v = &caps[i];

    if(code == BGP_CAP_MP && clen == 4){
      uint16_t afi = (uint16_t)(v[0]<<8 | v[1]);
      uint8_t safi = v[3];

      if(afi == 1  && safi == 1)    p->caps.mp_ipv4u = true;
      if(afi == 2  && safi == 1)    p->caps.mp_ipv6u = true;
      if(afi == 1  && safi == 128)  p->caps.mp_vpnv4 = true;
      if(afi == 25 && safi == 70)   p->caps.mp_evpn  = true;
      if(afi == 25 && safi == 65)   p->caps.mp_vpls  = true;

    } else if(code == BGP_CAP_AS4 && clen == 4){
      p->caps.as4 = true;
      p->caps.as4_value = (uint32_t)(v[0]<<24 | v[1]<<16 | v[2]<<8 | v[3]);

    } else if(code == BGP_CAP_GR && clen >= 2){
      p->caps.graceful_restart = true;
      uint16_t rt = (uint16_t)(v[0]<<8 | v[1]);
      p->caps.gr_time = (rt & 0x0FFF);

    } else if(code == BGP_CAP_RR && clen == 0){
      p->caps.route_refresh = true;
    }

    i += clen;
  }
}

static int parse_open(bgp_peer_t* p, const uint8_t* msg, size_t len){
  if(len < 19 + sizeof(bgp_open_fixed_t)) return -1;
  const bgp_open_fixed_t* o = (const bgp_open_fixed_t*)(msg + 19);
  if(o->version != 4) return -1;

  p->remote_asn = ntohs(o->my_as);
  p->remote_id = o->bgp_id;

  uint16_t hold = ntohs(o->hold_time);
  p->negotiated_hold = (hold < p->local_hold) ? hold : p->local_hold;

  caps_init(&p->caps);

  size_t opt_len = o->opt_len;
  size_t off = 19 + sizeof(bgp_open_fixed_t);
  if(off + opt_len > len) return -1;

  size_t i = 0;
  while(i + 2 <= opt_len){
    uint8_t ptype = msg[off + i];
    uint8_t plen  = msg[off + i + 1];
    i += 2;
    if(i + plen > opt_len) break;

    if(ptype == BGP_OPT_PARAM_CAPA){
      parse_caps(p, msg + off + i, plen);
    }
    i += plen;
  }

  log_msg(BGP_LOG_INFO,
          "RX OPEN remote-as(16)=%u hold=%u id=%s caps: ipv4u=%d vpnv4=%d evpn=%d vpls=%d rr=%d as4=%d gr=%d",
          p->remote_asn, hold, inet_ntoa(p->remote_id),
          p->caps.mp_ipv4u, p->caps.mp_vpnv4, p->caps.mp_evpn, p->caps.mp_vpls,
          p->caps.route_refresh, p->caps.as4, p->caps.graceful_restart);

  // Any RX message should refresh hold timer (OPEN included).
  bgp_peer_on_rx_message(p);
  return 0;
}

/* --- TX primitives --- */

int bgp_send_keepalive(bgp_peer_t* p){
  uint8_t buf[19];
  bgp_hdr_t* h = (bgp_hdr_t*)buf;

  fill_marker(h->marker);
  h->len  = htons(19);
  h->type = BGP_MSG_KEEPALIVE;

  log_msg(BGP_LOG_DEBUG, "TX KEEPALIVE to %s", inet_ntoa(p->addr));
  return send_all(p->fd, buf, sizeof(buf));
}

int bgp_send_notification(bgp_peer_t* p, uint8_t code, uint8_t subcode){
  uint8_t buf[21];
  bgp_hdr_t* h = (bgp_hdr_t*)buf;

  fill_marker(h->marker);
  h->len  = htons(21);
  h->type = BGP_MSG_NOTIFICATION;

  buf[19] = code;
  buf[20] = subcode;

  log_msg(BGP_LOG_WARN, "TX NOTIFICATION to %s code=%u sub=%u",
          inet_ntoa(p->addr), code, subcode);
  return send_all(p->fd, buf, sizeof(buf));
}

int bgp_send_open(bgp_peer_t* p){
  uint8_t buf[BGP_MAX_MSG];
  memset(buf, 0, sizeof(buf));

  bgp_hdr_t* h = (bgp_hdr_t*)buf;
  memset(h->marker, 0xFF, 16);
  h->type = BGP_MSG_OPEN;

  bgp_open_fixed_t* o = (bgp_open_fixed_t*)(buf + 19);
  o->version = 4;

  uint16_t my_as_16 = (p->local_asn > 65535) ? 23456 : (uint16_t)p->local_asn;
  o->my_as = htons(my_as_16);
  o->hold_time = htons(p->local_hold);
  o->bgp_id = p->local_id;

  uint8_t* opt = (uint8_t*)(buf + 19 + sizeof(bgp_open_fixed_t));
  uint8_t* param = opt;

  uint8_t* param_hdr = param;
  *param++ = BGP_OPT_PARAM_CAPA;
  *param++ = 0;

  uint8_t* caps_start = param;

  if(p->af_ipv4u_active)  param = add_cap_mp(param, 1, 1);
  if(p->af_ipv6u_active)  param = add_cap_mp(param, 2, 1);
  if(p->af_vpnv4_active)  param = add_cap_mp(param, 1, 128);
  if(p->af_evpn_active)   param = add_cap_mp(param, 25, 70);
  if(p->af_vpls_active)   param = add_cap_mp(param, 25, 65);

  param = add_cap_rr(param);
  param = add_cap_as4(param, p->local_asn);
  param = add_cap_gr(param, p->local_hold);

  size_t caps_len = (size_t)(param - caps_start);
  if(caps_len == 0){
    o->opt_len = 0;
    uint16_t tot = (uint16_t)(19 + sizeof(bgp_open_fixed_t));
    h->len = htons(tot);
    log_msg(BGP_LOG_INFO, "TX OPEN (no caps) local-as=%u id=%s",
            p->local_asn, inet_ntoa(p->local_id));
    return send_all(p->fd, buf, tot);
  }

  param_hdr[1] = (uint8_t)caps_len;

  size_t opt_len = (size_t)(param - opt);
  o->opt_len = (uint8_t)opt_len;

  uint16_t tot = (uint16_t)(19 + sizeof(bgp_open_fixed_t) + opt_len);
  h->len = htons(tot);

  log_msg(BGP_LOG_INFO,
          "TX OPEN local-as=%u id=%s caps: ipv4u=%d vpnv4=%d evpn=%d vpls=%d rr=1 as4=1 gr=1",
          p->local_asn, inet_ntoa(p->local_id),
          p->af_ipv4u_active, p->af_vpnv4_active, p->af_evpn_active, p->af_vpls_active);

  return send_all(p->fd, buf, tot);
}


int bgp_send_route_refresh(bgp_peer_t* p, uint16_t afi, uint8_t safi){
  if(!p || !p->caps.route_refresh) return -1;

  /* Route-Refresh message: 19-byte header + 4-byte payload (AFI/reserved/SAFI) */
  uint8_t buf[23];
  bgp_hdr_t* h = (bgp_hdr_t*)buf;
  fill_marker(h->marker);
  h->len  = htons(23);
  h->type = BGP_MSG_ROUTE_REFRESH;

  buf[19] = (uint8_t)(afi >> 8);
  buf[20] = (uint8_t)(afi);
  buf[21] = 0;          /* reserved */
  buf[22] = safi;

  log_msg(BGP_LOG_INFO, "TX ROUTE-REFRESH to %s afi=%u safi=%u",
          inet_ntoa(p->addr), afi, safi);
  return send_all(p->fd, buf, sizeof(buf));
}
/* Exported classic IPv4 UPDATE sender (kept as-is) */
int peer_send_update4(bgp_peer_t* p,
                      const struct in_addr* pfx, uint8_t plen,
                      const bgp_attrs_t* a,
                      bool withdraw)
{
  uint8_t msg[BGP_MAX_MSG];
  bgp_hdr_t* h = (bgp_hdr_t*)msg;

  fill_marker(h->marker);
  h->type = BGP_MSG_UPDATE;

  bgp_update4_t u;
  update4_init(&u);

  if(withdraw){
    u.withdrawn[0].pfx = *pfx;
    u.withdrawn[0].plen = plen;
    u.withdrawn_count = 1;
  } else {
    if(!a) return -1;
    u.attrs = *a;
    u.nlri[0].pfx = *pfx;
    u.nlri[0].plen = plen;
    u.nlri_count = 1;
  }

  bool is_ibgp = (p->local_asn == p->remote_asn_cfg);
  int pay = update4_encode(msg + 19, (int)sizeof(msg) - 19, &u, is_ibgp);
  if(pay < 0) return -1;

  h->len = htons((uint16_t)(19 + pay));

  log_msg(BGP_LOG_DEBUG, "TX UPDATE4 to %s %s %s/%u",
          inet_ntoa(p->addr),
          withdraw ? "withdraw" : "announce",
          inet_ntoa(*pfx), plen);

  return send_all(p->fd, msg, (size_t)(19 + pay));
}

/* MP UPDATE sender (AFI/SAFI like EVPN/VPLS) */
int peer_send_mp(bgp_peer_t* p,
                 uint16_t afi, uint8_t safi,
                 const bgp_attrs_t* attrs,
                 const uint8_t* nh, uint8_t nh_len,
                 const uint8_t* nlri, uint16_t nlri_len,
                 bool withdraw)
{
  if(!p) return -1;

  uint8_t msg[BGP_MAX_MSG];
  bgp_hdr_t* h = (bgp_hdr_t*)msg;

  fill_marker(h->marker);
  h->type = BGP_MSG_UPDATE;

  mp_reach_t r;
  mp_unreach_t u;
  memset(&r, 0, sizeof(r));
  memset(&u, 0, sizeof(u));

  if(withdraw){
    u.afi = afi;
    u.safi = safi;
    u.withdrawn = nlri;
    u.withdrawn_len = nlri_len;
  } else {
    r.afi = afi;
    r.safi = safi;

    if(nh_len == 0) return -1;                 // MP_REACH requires next-hop
    if(nh_len > sizeof(r.nh)) return -1;

    r.nh_len = nh_len;
    memcpy(r.nh, nh, nh_len);

    r.nlri = nlri;
    r.nlri_len = nlri_len;
  }

  bool is_ebgp = (p->local_asn != p->remote_asn_cfg);

  int pay = mp_update_encode(msg + 19, (int)sizeof(msg) - 19,
                             attrs,
                             is_ebgp, p->local_asn,
                             withdraw ? NULL : &r,
                             withdraw ? &u   : NULL);
  if(pay < 0) return -1;

  h->len = htons((uint16_t)(19 + pay));

  log_msg(BGP_LOG_DEBUG, "TX MP UPDATE to %s afi=%u safi=%u %s (nlri=%u)",
          inet_ntoa(p->addr), afi, safi,
          withdraw ? "withdraw" : "announce",
          (unsigned)nlri_len);

  return send_all(p->fd, msg, (size_t)(19 + pay));
}

/* --- RX processing --- */

int bgp_rx_process(bgp_peer_t* p){
  for(;;){
    ssize_t n = recv(p->fd, p->rxbuf + p->rxlen, sizeof(p->rxbuf) - p->rxlen, 0);
    if(n < 0){
      if(errno == EINTR) continue;
      if(errno == EAGAIN || errno == EWOULDBLOCK) break;
      return -1;
    }
    if(n == 0) return -1;
    p->rxlen += (size_t)n;

    while(p->rxlen >= 19){
      bgp_hdr_t h;
      if(parse_hdr(p->rxbuf, p->rxlen, &h) < 0) return -1;
      if(p->rxlen < h.len) break;

      const uint8_t* msg = p->rxbuf;
      size_t msglen = h.len;

      switch(h.type){
        case BGP_MSG_OPEN:
          if(parse_open(p, msg, msglen) < 0) return -1;
          bgp_fsm_event(p, BGP_EVT_RX_OPEN);
          break;

        case BGP_MSG_KEEPALIVE:
          log_msg(BGP_LOG_DEBUG, "RX KEEPALIVE from %s", inet_ntoa(p->addr));
          bgp_peer_on_rx_message(p);
          bgp_fsm_event(p, BGP_EVT_RX_KEEPALIVE);
          break;

        case BGP_MSG_NOTIFICATION:
          log_msg(BGP_LOG_WARN, "RX NOTIFICATION from %s", inet_ntoa(p->addr));
          bgp_peer_on_rx_message(p);
          bgp_fsm_event(p, BGP_EVT_RX_NOTIFICATION);

          // IMPORTANT: stop processing immediately.
          // FSM likely closed fd / cleared rx state; continuing risks UAF/segfault.
          return -2;

        case BGP_MSG_UPDATE: {
          log_msg(BGP_LOG_DEBUG, "RX UPDATE from %s", inet_ntoa(p->addr));
          bgp_peer_on_rx_message(p);

          bool is_ebgp = (p->local_asn != p->remote_asn_cfg);

          /* Locate the raw path-attributes slice for MP-family decoders.
           * UPDATE payload (after 19-byte header): withdrawn_len(2) + withdrawn
           * + path_attr_len(2) + path_attrs + nlri.
           * vpnv4_from_mp_attrs needs the raw attrs bytes. */
          const uint8_t *pay = msg + 19;
          int pay_len = (int)msglen - 19;
          const uint8_t *attrs_raw = NULL;
          int attrs_raw_len = 0;
          if(pay_len >= 4){
            int wlen = (pay[0] << 8) | pay[1];
            if(2 + wlen + 2 <= pay_len){
              attrs_raw_len = (pay[2 + wlen] << 8) | pay[2 + wlen + 1];
              if(2 + wlen + 2 + attrs_raw_len <= pay_len){
                attrs_raw = pay + 2 + wlen + 2;
              }
            }
          }

          /* Classic IPv4 unicast: always decode (attrs may also carry MP) */
          bgp_update4_t u;
          update4_init(&u);
          if(update4_decode(&u, msg, (int)msglen, is_ebgp) < 0) return -1;

          if(p->core){
            /* IPv4 unicast */
            if(p->caps.mp_ipv4u || u.nlri_count > 0 || u.withdrawn_count > 0){
              core_on_update4(p->core, p, &u);
            }

            /* VPNv4 */
            if(p->caps.mp_vpnv4 && attrs_raw){
              vpnv4_update_t vu;
              vpnv4_update_init(&vu);
              if(vpnv4_from_mp_attrs(&vu, attrs_raw, attrs_raw_len) == 0){
                core_on_vpnv4(p->core, p, &vu);
              }
            }

            /* EVPN and VPLS: pass the raw path-attribute bytes so the
             * handlers can extract the MP_REACH / MP_UNREACH NLRI blobs
             * (AFI=25) and fully decode them. */
            if(p->caps.mp_evpn){
              log_msg(BGP_LOG_DEBUG, "RX EVPN UPDATE from %s", inet_ntoa(p->addr));
              core_on_evpn_update(p->core, p, attrs_raw, attrs_raw_len);
            }
            if(p->caps.mp_vpls){
              log_msg(BGP_LOG_DEBUG, "RX VPLS UPDATE from %s", inet_ntoa(p->addr));
              core_on_vpls_update(p->core, p, attrs_raw, attrs_raw_len);
            }
          }
          break;
        }

        case BGP_MSG_ROUTE_REFRESH: {
          /* RFC 2918: peer is requesting a full re-advertisement for afi/safi */
          bgp_peer_on_rx_message(p);
          if(msglen >= 23){
            uint16_t rr_afi  = (uint16_t)((msg[19] << 8) | msg[20]);
            uint8_t  rr_safi = msg[22];
            log_msg(BGP_LOG_INFO, "RX ROUTE-REFRESH from %s afi=%u safi=%u",
                    inet_ntoa(p->addr), rr_afi, rr_safi);
          } else {
            log_msg(BGP_LOG_INFO, "RX ROUTE-REFRESH from %s (short)", inet_ntoa(p->addr));
          }
          /* Re-trigger full advertisement for this peer */
          if(p->core) core_on_established(p->core, p);
          break;
        }

        default:
          log_msg(BGP_LOG_WARN, "RX unknown type=%u from %s", h.type, inet_ntoa(p->addr));
          return -1;
      }

      // If FSM closed the session during the event, stop cleanly.
      if(p->fd < 0) return -1;

      memmove(p->rxbuf, p->rxbuf + msglen, p->rxlen - msglen);
      p->rxlen -= msglen;
    }
  }
  return 0;
}
