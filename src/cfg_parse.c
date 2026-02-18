// src/cfg_parse.c
#include "bgp/bgp.h"
#include "bgp/policy.h"
#include "bgp/vrf.h"
#include "bgp/cfg.h"
#include "bgp/log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <ctype.h>

typedef enum { TOK_EOF=0, TOK_WORD, TOK_EOL, TOK_BANG } tok_kind_t;
typedef struct { tok_kind_t k; char s[128]; } token_t;

extern void*   cfg_lx_open(FILE* f);
extern token_t cfg_lx_next(void* st);
extern void    cfg_lx_close(void* st);

typedef struct {
  void* lx;
  token_t cur;

  int in_router_bgp;

  // address-family context:
  // 0 = none
  // 1 = ipv4 unicast
  // 2 = ipv6 unicast
  // 3 = ipv4 vrf (vpnv4 capability)
  // 4 = l2vpn evpn
  // 5 = l2vpn vpls
  int af_ctx;
  char af_vrf_name[64]; /* VRF name when af_ctx == 3 */

  int line;
} parser_t;

static void next(parser_t* p){
  p->cur = cfg_lx_next(p->lx);
  if(p->cur.k == TOK_EOL) p->line++;
}

static int is(parser_t* p, tok_kind_t k, const char* s){
  if(p->cur.k != k) return 0;
  if(!s) return 1;
  return strcasecmp(p->cur.s, s) == 0;
}

static void skip_line(parser_t* p){
  while(p->cur.k != TOK_EOF && p->cur.k != TOK_EOL) next(p);
  if(p->cur.k == TOK_EOL) next(p);
}

static int parse_ipv4(const char* s, struct in_addr* out){
  return inet_aton(s, out) ? 0 : -1;
}

static int parse_prefix4(const char* s, struct in_addr* out, uint8_t* plen){
  // "a.b.c.d/len"
  char tmp[64];
  memset(tmp, 0, sizeof(tmp));
  strncpy(tmp, s, sizeof(tmp)-1);

  char* slash = strchr(tmp, '/');
  if(!slash) return -1;
  *slash = 0;

  int p = atoi(slash+1);
  if(p < 0 || p > 32) return -1;

  struct in_addr a;
  if(parse_ipv4(tmp, &a) < 0) return -1;

  *out = a;
  *plen = (uint8_t)p;
  return 0;
}

static int parse_prefix6(const char* s, struct in6_addr* out, int* plen){
  // "2001:db8::/32"
  char tmp[128];
  memset(tmp, 0, sizeof(tmp));
  strncpy(tmp, s, sizeof(tmp)-1);

  char* slash = strchr(tmp, '/');
  if(!slash) return -1;
  *slash = 0;

  int p = atoi(slash+1);
  if(p < 0 || p > 128) return -1;

  struct in6_addr a;
  if(inet_pton(AF_INET6, tmp, &a) != 1) return -1;

  *out = a;
  *plen = p;
  return 0;
}

/**
 * Collect description text until end of line.
 * Handles quoted strings and multiple words.
 * Removes leading/trailing quotes if present.
 */
static void parse_description(parser_t* p, char* dest, size_t destlen)
{
  if (!dest || destlen == 0) return;

  char buf[256] = {0};
  int in_quotes = 0;
  int pos = 0;

  /* First token check: is it quoted? */
  if (p->cur.k == TOK_WORD && p->cur.s[0] == '"') {
    in_quotes = 1;
    /* Skip leading quote and copy rest of token */
    const char* src = p->cur.s + 1;
    while (*src && *src != '"' && pos < (int)sizeof(buf) - 1) {
      buf[pos++] = *src++;
    }
    /* Check if closing quote is in same token */
    if (*src == '"') {
      in_quotes = 0;
      next(p);
    } else {
      /* Quote continues to next token(s), add space and process remaining tokens */
      if (pos < (int)sizeof(buf) - 1) buf[pos++] = ' ';
      next(p);

      /* Collect remaining tokens until closing quote */
      while (p->cur.k == TOK_WORD && in_quotes) {
        const char* src = p->cur.s;
        int found_close = 0;
        while (*src && pos < (int)sizeof(buf) - 1) {
          if (*src == '"') {
            found_close = 1;
            break;
          }
          buf[pos++] = *src++;
        }
        if (found_close) {
          in_quotes = 0;
          next(p);
          break;
        }
        /* No closing quote yet, add space and continue */
        if (pos < (int)sizeof(buf) - 1) buf[pos++] = ' ';
        next(p);
      }
    }
  } else if (p->cur.k == TOK_WORD) {
    /* Unquoted single token description */
    const char* src = p->cur.s;
    while (*src && pos < (int)sizeof(buf) - 1) {
      buf[pos++] = *src++;
    }
    next(p);
  }

  buf[pos] = '\0';

  /* Copy to destination, limiting length */
  strncpy(dest, buf, destlen - 1);
  dest[destlen - 1] = '\0';
}

static int word_is_neighbor(const char* s){
  return (strcasecmp(s, "neighbor") == 0) || (strcasecmp(s, "neightbor") == 0);
}

static bgp_neighbor_cfg_t* find_neighbor(bgp_config_t* cfg, struct in_addr a){
  for(int i=0;i<cfg->neighbor_count;i++){
    if(cfg->neighbors[i].addr.s_addr == a.s_addr) return &cfg->neighbors[i];
  }
  return NULL;
}

static bgp_neighbor_cfg_t* get_or_add_neighbor(bgp_config_t* cfg, struct in_addr a){
  bgp_neighbor_cfg_t* n = find_neighbor(cfg, a);
  if(n) return n;

  if(cfg->neighbor_count >= (int)(sizeof(cfg->neighbors)/sizeof(cfg->neighbors[0])))
    return NULL;

  n = &cfg->neighbors[cfg->neighbor_count++];
  memset(n, 0, sizeof(*n));
  n->addr = a;

  // inherit global defaults
  n->hold_time = cfg->params.hold_time;
  n->keepalive = cfg->params.keepalive;
  return n;
}

static void set_neighbor_activate_by_af(parser_t* p, bgp_neighbor_cfg_t* n){
  if(!n) return;
  switch(p->af_ctx){
    case 1: n->af_ipv4u_active = true; break;
    case 2: n->af_ipv6u_active = true; break;
    case 3: n->af_vpnv4_active = true; break;
    case 4: n->af_evpn_active  = true; break;
    case 5: n->af_vpls_active  = true; break;
    default: break;
  }
}

int bgp_load_config(bgp_config_t* out, const char* path){
  if(!out || !path) return -1;
  memset(out, 0, sizeof(*out));

  // defaults
  out->params.hold_time = 180;
  out->params.keepalive = 60;
  out->default_ipv4_unicast = true;  /* enabled by default */

  FILE* f = fopen(path, "r");
  if(!f){
    log_msg(BGP_LOG_ERROR, "open config '%s' failed", path);
    return -1;
  }

  parser_t P;
  memset(&P, 0, sizeof(P));
  P.lx = cfg_lx_open(f);
  P.in_router_bgp = 0;
  P.af_ctx = 0;
  P.line = 1;

  next(&P);

  while(P.cur.k != TOK_EOF){
    if(P.cur.k == TOK_EOL){
      next(&P);
      continue;
    }
    if(P.cur.k == TOK_BANG){
      skip_line(&P);
      continue;
    }

    /* ── vrf definition <name> ────────────────────────────────────────────
     *   rd <ASN:NN>
     *   route-target import <ASN:NN>
     *   route-target export <ASN:NN>
     *   table <N>
     *   vni <N>
     *   bridge <iface>
     * ──────────────────────────────────────────────────────────────────── */
    if(is(&P, TOK_WORD, "vrf")){
      next(&P);
      if(!is(&P, TOK_WORD, "definition")){ skip_line(&P); continue; }
      next(&P);
      if(P.cur.k != TOK_WORD){ skip_line(&P); continue; }
      char vname[64];
      strncpy(vname, P.cur.s, sizeof(vname)-1);
      vname[sizeof(vname)-1] = 0;
      skip_line(&P);

      vrf_t* v = vrf_get(&out->vrfs, vname, 1);
      if(!v){ skip_line(&P); continue; }

      while(P.cur.k != TOK_EOF && P.cur.k != TOK_BANG){
        if(P.cur.k == TOK_EOL){ next(&P); continue; }

        if(is(&P, TOK_WORD, "rd")){
          next(&P);
          if(P.cur.k == TOK_WORD){
            char* colon = strchr(P.cur.s, ':');
            if(colon){
              *colon = 0;
              v->rd.asn = (uint32_t)strtoul(P.cur.s, NULL, 10);
              v->rd.val = (uint32_t)strtoul(colon+1, NULL, 10);
            }
          }
          skip_line(&P); continue;
        }

        if(is(&P, TOK_WORD, "route-target")){
          next(&P);
          int is_import = is(&P, TOK_WORD, "import");
          int is_export = is(&P, TOK_WORD, "export");
          if(!is_import && !is_export){ skip_line(&P); continue; }
          next(&P);
          if(P.cur.k == TOK_WORD){
            char* colon = strchr(P.cur.s, ':');
            if(colon){
              rt_asn_t rt;
              *colon = 0;
              rt.asn = (uint32_t)strtoul(P.cur.s, NULL, 10);
              rt.val = (uint32_t)strtoul(colon+1, NULL, 10);
              if(is_import && v->import_count < 64)
                v->import_rts[v->import_count++] = rt;
              if(is_export && v->export_count < 64)
                v->export_rts[v->export_count++] = rt;
            }
          }
          skip_line(&P); continue;
        }

        if(is(&P, TOK_WORD, "table")){
          next(&P);
          if(P.cur.k == TOK_WORD) v->table_id = atoi(P.cur.s);
          skip_line(&P); continue;
        }

        if(is(&P, TOK_WORD, "vni")){
          next(&P);
          if(P.cur.k == TOK_WORD) v->vni = (uint32_t)strtoul(P.cur.s, NULL, 10);
          skip_line(&P); continue;
        }

        if(is(&P, TOK_WORD, "bridge")){
          next(&P);
          if(P.cur.k == TOK_WORD){
            strncpy(v->bridge, P.cur.s, sizeof(v->bridge)-1);
            v->bridge[sizeof(v->bridge)-1] = 0;
          }
          skip_line(&P); continue;
        }

        if(is(&P, TOK_WORD, "address-family") ||
           is(&P, TOK_WORD, "exit-vrf")){
          skip_line(&P); continue;
        }

        skip_line(&P);
      }
      continue;
    }

    /* ── interface <name> ───────────────────────────────────────────────────
     *   ip address <addr>/<prefix>
     *   ipv6 address <addr>/<prefix>
     *   description "<text>"
     *   mtu <N>
     *   shutdown | no shutdown
     * ──────────────────────────────────────────────────────────────────── */
    if(is(&P, TOK_WORD, "interface")){
      next(&P);
      if(P.cur.k != TOK_WORD){ skip_line(&P); continue; }

      char ifname[16];
      strncpy(ifname, P.cur.s, sizeof(ifname)-1);
      ifname[sizeof(ifname)-1] = 0;
      skip_line(&P);

      /* Find or create interface in config */
      interface_cfg_t* iface = NULL;
      if(out->interface_count < 64){
        iface = &out->interfaces[out->interface_count];
        strncpy(iface->name, ifname, sizeof(iface->name)-1);
        iface->name[sizeof(iface->name)-1] = 0;
        out->interface_count++;
      }

      if(!iface){ skip_line(&P); continue; }

      while(P.cur.k != TOK_EOF && P.cur.k != TOK_BANG){
        if(P.cur.k == TOK_EOL){ next(&P); continue; }

        if(is(&P, TOK_WORD, "ip")){
          next(&P);
          if(is(&P, TOK_WORD, "address")){
            next(&P);
            if(P.cur.k == TOK_WORD){
              char addr_copy[64];
              strncpy(addr_copy, P.cur.s, sizeof(addr_copy)-1);
              addr_copy[sizeof(addr_copy)-1] = 0;
              char* slash = strchr(addr_copy, '/');
              if(slash){
                *slash = 0;
                int plen = atoi(slash + 1);
                if(plen > 0 && plen <= 32){
                  inet_aton(addr_copy, &iface->addr_v4);
                  iface->plen_v4 = (uint8_t)plen;
                }
              }
            }
            skip_line(&P); continue;
          }
          skip_line(&P); continue;
        }

        if(is(&P, TOK_WORD, "ipv6")){
          next(&P);
          if(is(&P, TOK_WORD, "address")){
            next(&P);
            if(P.cur.k == TOK_WORD){
              char addr_copy[128];
              strncpy(addr_copy, P.cur.s, sizeof(addr_copy)-1);
              addr_copy[sizeof(addr_copy)-1] = 0;
              char* slash = strchr(addr_copy, '/');
              if(slash){
                *slash = 0;
                int plen = atoi(slash + 1);
                if(plen > 0 && plen <= 128){
                  inet_pton(AF_INET6, addr_copy, &iface->addr_v6);
                  iface->plen_v6 = (uint8_t)plen;
                }
              }
            }
            skip_line(&P); continue;
          }
          skip_line(&P); continue;
        }

        if(is(&P, TOK_WORD, "description")){
          next(&P);
          if(P.cur.k == TOK_WORD){
            parse_description(&P, iface->description, sizeof(iface->description));
          }
          skip_line(&P); continue;
        }

        if(is(&P, TOK_WORD, "mtu")){
          next(&P);
          if(P.cur.k == TOK_WORD){
            int mtu = atoi(P.cur.s);
            if(mtu >= 68 && mtu <= 65535) iface->mtu = (uint32_t)mtu;
          }
          skip_line(&P); continue;
        }

        if(is(&P, TOK_WORD, "shutdown")){
          iface->shutdown = 1;
          skip_line(&P); continue;
        }

        if(is(&P, TOK_WORD, "no")){
          next(&P);
          if(is(&P, TOK_WORD, "shutdown")){
            iface->shutdown = 0;
          }
          skip_line(&P); continue;
        }

        skip_line(&P);
      }

      next(&P); /* skip the ! */
      continue;
    }

    /* ── ip route <prefix>/<len> { via <nexthop> | dev <ifname> } ...
     *       ... [dev <ifname>] [via <nexthop>] [table <id>]
     * Examples:
     *   ip route 10.0.0.0/8 via 192.168.1.1
     *   ip route 10.0.0.0/8 dev eth0
     *   ip route 10.0.0.0/8 via 192.168.1.1 dev eth0
     *   ip route 0.0.0.0/0  via 192.168.1.1 table 200
     * ──────────────────────────────────────────────────────────────────── */
    if(is(&P, TOK_WORD, "ip")){
      next(&P);

      if(is(&P, TOK_WORD, "route")){
        next(&P);
        if(P.cur.k != TOK_WORD){ skip_line(&P); continue; }

        struct in_addr pfx = {0};
        uint8_t plen = 0;
        if(parse_prefix4(P.cur.s, &pfx, &plen) < 0){ skip_line(&P); continue; }
        next(&P);

        static_route_t sr;
        memset(&sr, 0, sizeof(sr));
        sr.prefix = pfx;
        sr.plen   = plen;

        /* Parse optional keywords: via, dev, table in any order */
        while(P.cur.k == TOK_WORD){
          if(is(&P, TOK_WORD, "via")){
            next(&P);
            if(P.cur.k == TOK_WORD){
              parse_ipv4(P.cur.s, &sr.nexthop);
              next(&P);
            }
            continue;
          }
          if(is(&P, TOK_WORD, "dev")){
            next(&P);
            if(P.cur.k == TOK_WORD){
              strncpy(sr.ifname, P.cur.s, sizeof(sr.ifname)-1);
              sr.ifname[sizeof(sr.ifname)-1] = 0;
              next(&P);
            }
            continue;
          }
          if(is(&P, TOK_WORD, "table")){
            next(&P);
            if(P.cur.k == TOK_WORD){
              sr.table = atoi(P.cur.s);
              next(&P);
            }
            continue;
          }
          /* Positional nexthop (legacy: ip route <pfx> <nexthop>) */
          if(sr.nexthop.s_addr == 0 && sr.ifname[0] == 0){
            struct in_addr maybe_nh = {0};
            if(parse_ipv4(P.cur.s, &maybe_nh) == 0){
              sr.nexthop = maybe_nh;
              next(&P);
              continue;
            }
          }
          break;
        }

        if(sr.nexthop.s_addr == 0 && sr.ifname[0] == 0){
          log_msg(BGP_LOG_WARN,
                  "config line %d: ip route %s/%u: need 'via <nexthop>' or 'dev <ifname>'",
                  P.line, inet_ntoa(pfx), plen);
          skip_line(&P); continue;
        }

        if(out->static_route_count <
           (int)(sizeof(out->static_routes)/sizeof(out->static_routes[0]))){
          out->static_routes[out->static_route_count++] = sr;
        }
        skip_line(&P);
        continue;
      }

      if(!is(&P, TOK_WORD, "prefix-list")){ skip_line(&P); continue; }
      next(&P);
      if(P.cur.k != TOK_WORD){ skip_line(&P); continue; }
      char plname[64];
      strncpy(plname, P.cur.s, sizeof(plname)-1);
      plname[sizeof(plname)-1] = 0;
      next(&P);

      int seq = 0;
      if(is(&P, TOK_WORD, "seq")){
        next(&P);
        if(P.cur.k == TOK_WORD){ seq = atoi(P.cur.s); next(&P); }
      }

      bool permit = true;
      if(is(&P, TOK_WORD, "permit"))       { permit = true;  next(&P); }
      else if(is(&P, TOK_WORD, "deny"))    { permit = false; next(&P); }

      struct in_addr pfx = {0};
      uint8_t plen = 0;
      if(P.cur.k == TOK_WORD && parse_prefix4(P.cur.s, &pfx, &plen) == 0){
        next(&P);
        prefix_list_t* pl = policy_get_plist(&out->policy, plname, true);
        if(pl && pl->rule_count < 256){
          prefix_list_rule_t* r = &pl->rules[pl->rule_count++];
          memset(r, 0, sizeof(*r));
          strncpy(r->name, plname, sizeof(r->name)-1);
          r->seq = (seq > 0) ? seq : pl->rule_count * 10;
          r->permit = permit;
          r->pfx = pfx;
          r->plen = plen;
          /* optional ge / le */
          if(is(&P, TOK_WORD, "ge")){ next(&P); if(P.cur.k==TOK_WORD){ r->ge=(uint8_t)atoi(P.cur.s); next(&P); } }
          if(is(&P, TOK_WORD, "le")){ next(&P); if(P.cur.k==TOK_WORD){ r->le=(uint8_t)atoi(P.cur.s); next(&P); } }
        }
      }
      skip_line(&P);
      continue;
    }

    /* ── route-map <name> permit|deny <seq> ────────────────────────────────
     *   match ip address prefix-list NAME
     *   match community NAME
     *   set local-preference N
     *   set metric N
     *   set ip next-hop self
     *   set community N:N [additive]
     *   set as-path prepend <asn> [<asn>...]
     * ──────────────────────────────────────────────────────────────────── */
    if(is(&P, TOK_WORD, "route-map")){
      next(&P);
      if(P.cur.k != TOK_WORD){ skip_line(&P); continue; }
      char rmname[64];
      strncpy(rmname, P.cur.s, sizeof(rmname)-1);
      rmname[sizeof(rmname)-1] = 0;
      next(&P);

      bool permit = true;
      if(is(&P, TOK_WORD, "permit"))       { permit = true;  next(&P); }
      else if(is(&P, TOK_WORD, "deny"))    { permit = false; next(&P); }

      int seq = 10;
      if(P.cur.k == TOK_WORD){ seq = atoi(P.cur.s); next(&P); }
      skip_line(&P);

      route_map_t* rm = policy_get_rmap(&out->policy, rmname, true);
      if(!rm){ continue; }

      route_map_entry_t* ent = NULL;
      if(rm->ent_count < 128){
        ent = &rm->ents[rm->ent_count++];
        memset(ent, 0, sizeof(*ent));
        strncpy(ent->name, rmname, sizeof(ent->name)-1);
        ent->seq = seq;
        ent->permit = permit;
      }

      /* Parse the clause body until the next '!' or 'route-map' or EOF */
      while(P.cur.k != TOK_EOF && P.cur.k != TOK_BANG){
        if(P.cur.k == TOK_EOL){ next(&P); continue; }

        /* match ip address prefix-list NAME */
        if(is(&P, TOK_WORD, "match")){
          next(&P);
          if(is(&P, TOK_WORD, "ip")){
            next(&P);
            if(is(&P, TOK_WORD, "address")){
              next(&P);
              if(is(&P, TOK_WORD, "prefix-list")){
                next(&P);
                if(ent && P.cur.k == TOK_WORD)
                  strncpy(ent->match_plist, P.cur.s, sizeof(ent->match_plist)-1);
              }
            }
          } else if(is(&P, TOK_WORD, "community")){
            next(&P);
            if(ent && P.cur.k == TOK_WORD)
              strncpy(ent->match_community, P.cur.s, sizeof(ent->match_community)-1);
          }
          skip_line(&P); continue;
        }

        /* set ... */
        if(is(&P, TOK_WORD, "set")){
          next(&P);

          if(is(&P, TOK_WORD, "local-preference")){
            next(&P);
            if(ent && P.cur.k == TOK_WORD){
              ent->set_local_pref = true;
              ent->local_pref = (uint32_t)strtoul(P.cur.s, NULL, 10);
            }
            skip_line(&P); continue;
          }

          if(is(&P, TOK_WORD, "metric")){
            next(&P);
            if(ent && P.cur.k == TOK_WORD){
              ent->set_med = true;
              ent->med = (uint32_t)strtoul(P.cur.s, NULL, 10);
            }
            skip_line(&P); continue;
          }

          if(is(&P, TOK_WORD, "ip")){
            next(&P);
            if(is(&P, TOK_WORD, "next-hop")){
              next(&P);
              if(is(&P, TOK_WORD, "self") && ent){
                ent->set_next_hop_self = true;
              }
            }
            skip_line(&P); continue;
          }

          if(is(&P, TOK_WORD, "community")){
            next(&P);
            if(ent){
              ent->set_community = true;
              ent->community_count = 0;
              while(P.cur.k == TOK_WORD &&
                    !is(&P, TOK_WORD, "additive") &&
                    ent->community_count < 32){
                /* parse N:N or 0xHHHHHHHH */
                char* colon = strchr(P.cur.s, ':');
                if(colon){
                  *colon = 0;
                  uint32_t hi = (uint32_t)strtoul(P.cur.s, NULL, 10);
                  uint32_t lo = (uint32_t)strtoul(colon+1, NULL, 10);
                  ent->community[ent->community_count++] = (hi<<16)|lo;
                } else {
                  ent->community[ent->community_count++] =
                      (uint32_t)strtoul(P.cur.s, NULL, 0);
                }
                next(&P);
              }
              if(is(&P, TOK_WORD, "additive")){
                ent->community_additive = true;
                next(&P);
              }
            }
            skip_line(&P); continue;
          }

          if(is(&P, TOK_WORD, "as-path")){
            next(&P);
            if(is(&P, TOK_WORD, "prepend") && ent){
              next(&P);
              ent->set_as_path_prepend = true;
              ent->prepend_count = 0;
              if(P.cur.k == TOK_WORD){
                ent->prepend_asn = (uint32_t)strtoul(P.cur.s, NULL, 10);
                ent->prepend_count = 1;
                next(&P);
                /* count repeated ASNs (e.g. "set as-path prepend 65001 65001") */
                while(P.cur.k == TOK_WORD &&
                      strtoul(P.cur.s, NULL, 10) == ent->prepend_asn){
                  ent->prepend_count++;
                  next(&P);
                }
              }
            }
            skip_line(&P); continue;
          }

          skip_line(&P); continue;
        }

        /* peek ahead: if next line starts a new route-map entry, stop */
        if(is(&P, TOK_WORD, "route-map")) break;

        skip_line(&P);
      }
      continue;
    }

    // router bgp <asn>
    if(is(&P, TOK_WORD, "router")){
      next(&P);
      if(is(&P, TOK_WORD, "bgp")){
        next(&P);
        if(P.cur.k != TOK_WORD){
          log_msg(BGP_LOG_ERROR, "config line %d: expected ASN after 'router bgp'", P.line);
          cfg_lx_close(P.lx); fclose(f);
          return -1;
        }
        out->params.asn = (uint32_t)strtoul(P.cur.s, NULL, 10);
        P.in_router_bgp = 1;
        P.af_ctx = 0;
        skip_line(&P);
        continue;
      }
      skip_line(&P);
      continue;
    }

    if(P.in_router_bgp){
      /* Handle comment lines (! at beginning) */
      if(P.cur.k == TOK_BANG){
        skip_line(&P);
        continue;
      }

      // bgp router-id / cluster-id / timers / default-ipv4-unicast
      if(is(&P, TOK_WORD, "bgp")){
        next(&P);

        if(is(&P, TOK_WORD, "router-id")){
          next(&P);
          struct in_addr rid;
          if(P.cur.k != TOK_WORD || parse_ipv4(P.cur.s, &rid) < 0){
            log_msg(BGP_LOG_ERROR, "config line %d: bad router-id", P.line);
            cfg_lx_close(P.lx); fclose(f);
            return -1;
          }
          out->params.router_id = rid;
          skip_line(&P);
          continue;
        }

        if(is(&P, TOK_WORD, "cluster-id")){
          next(&P);
          struct in_addr cid;
          if(P.cur.k != TOK_WORD || parse_ipv4(P.cur.s, &cid) < 0){
            log_msg(BGP_LOG_ERROR, "config line %d: bad cluster-id", P.line);
            cfg_lx_close(P.lx); fclose(f);
            return -1;
          }
          out->cluster_id = cid;
          skip_line(&P);
          continue;
        }

        if(is(&P, TOK_WORD, "timers")){
          next(&P);
          if(P.cur.k == TOK_WORD){
            uint16_t ka = (uint16_t)atoi(P.cur.s);
            next(&P);
            if(P.cur.k == TOK_WORD){
              uint16_t hold = (uint16_t)atoi(P.cur.s);
              out->params.keepalive = ka;
              out->params.hold_time = hold;
            }
          }
          skip_line(&P);
          continue;
        }

        if(is(&P, TOK_WORD, "default-ipv4-unicast")){
          out->default_ipv4_unicast = true;
          skip_line(&P);
          continue;
        }

        skip_line(&P);
        continue;
      }

      if(is(&P, TOK_WORD, "no")){
        next(&P);
        if(is(&P, TOK_WORD, "bgp")){
          next(&P);
          if(is(&P, TOK_WORD, "default-ipv4-unicast")){
            out->default_ipv4_unicast = false;
            skip_line(&P);
            continue;
          }
        }
        skip_line(&P);
        continue;
      }

      // address-family ...
      if(is(&P, TOK_WORD, "address-family")){
        next(&P);

        // ipv4 ...
        if(is(&P, TOK_WORD, "ipv4")){
          next(&P);
          if(is(&P, TOK_WORD, "unicast")){
            P.af_ctx = 1;
            skip_line(&P);
            continue;
          }
          if(is(&P, TOK_WORD, "vrf")){
            next(&P);
            if(P.cur.k == TOK_WORD){
              P.af_ctx = 3; // vpnv4 capability
              strncpy(P.af_vrf_name, P.cur.s, sizeof(P.af_vrf_name)-1);
              P.af_vrf_name[sizeof(P.af_vrf_name)-1] = 0;
              skip_line(&P);
              continue;
            }
          }
          P.af_ctx = 0;
          skip_line(&P);
          continue;
        }

        // ipv6 ...
        if(is(&P, TOK_WORD, "ipv6")){
          next(&P);
          if(is(&P, TOK_WORD, "unicast")){
            P.af_ctx = 2;
            skip_line(&P);
            continue;
          }
          P.af_ctx = 0;
          skip_line(&P);
          continue;
        }

        // l2vpn ...
        if(is(&P, TOK_WORD, "l2vpn")){
          next(&P);
          if(is(&P, TOK_WORD, "evpn")){
            P.af_ctx = 4;
            skip_line(&P);
            continue;
          }
          if(is(&P, TOK_WORD, "vpls")){
            P.af_ctx = 5;
            skip_line(&P);
            continue;
          }
          P.af_ctx = 0;
          skip_line(&P);
          continue;
        }

        P.af_ctx = 0;
        skip_line(&P);
        continue;
      }

      if(is(&P, TOK_WORD, "exit-address-family")){
        P.af_ctx = 0;
        P.af_vrf_name[0] = 0;
        skip_line(&P);
        continue;
      }

      // neighbor X activate (inside address-family context)
      if(P.af_ctx != 0 && P.cur.k == TOK_WORD && word_is_neighbor(P.cur.s)){
        next(&P);
        if(P.cur.k != TOK_WORD){
          log_msg(BGP_LOG_ERROR, "config line %d: expected neighbor IP in address-family", P.line);
          cfg_lx_close(P.lx); fclose(f);
          return -1;
        }

        struct in_addr nhip;
        if(parse_ipv4(P.cur.s, &nhip) < 0){
          log_msg(BGP_LOG_ERROR, "config line %d: bad neighbor IP in address-family", P.line);
          cfg_lx_close(P.lx); fclose(f);
          return -1;
        }

        bgp_neighbor_cfg_t* n = get_or_add_neighbor(out, nhip);
        if(!n){
          log_msg(BGP_LOG_ERROR, "config line %d: too many neighbors", P.line);
          cfg_lx_close(P.lx); fclose(f);
          return -1;
        }

        next(&P);

        // Look for "activate" command
        if(is(&P, TOK_WORD, "activate")){
          set_neighbor_activate_by_af(&P, n);
          skip_line(&P);
          continue;
        }

        skip_line(&P);
        continue;
      }

      // neighbor ...
      if(P.cur.k == TOK_WORD && word_is_neighbor(P.cur.s)){
        next(&P);
        if(P.cur.k != TOK_WORD){
          log_msg(BGP_LOG_ERROR, "config line %d: expected neighbor IP", P.line);
          cfg_lx_close(P.lx); fclose(f);
          return -1;
        }

        struct in_addr nhip;
        if(parse_ipv4(P.cur.s, &nhip) < 0){
          log_msg(BGP_LOG_ERROR, "config line %d: bad neighbor IP", P.line);
          cfg_lx_close(P.lx); fclose(f);
          return -1;
        }

        bgp_neighbor_cfg_t* n = get_or_add_neighbor(out, nhip);
        if(!n){
          log_msg(BGP_LOG_ERROR, "config line %d: too many neighbors", P.line);
          cfg_lx_close(P.lx); fclose(f);
          return -1;
        }

        next(&P);

        if(is(&P, TOK_WORD, "remote-as")){
          next(&P);
          if(P.cur.k != TOK_WORD){
            log_msg(BGP_LOG_ERROR, "config line %d: expected ASN after remote-as", P.line);
            cfg_lx_close(P.lx); fclose(f);
            return -1;
          }
          n->remote_asn = (uint32_t)strtoul(P.cur.s, NULL, 10);
          skip_line(&P);
          continue;
        }

        if(is(&P, TOK_WORD, "description")){
          next(&P);
          if(P.cur.k == TOK_WORD){
            parse_description(&P, n->description, sizeof(n->description));
          }
          skip_line(&P);
          continue;
        }

        if(is(&P, TOK_WORD, "route-map")){
          next(&P);
          if(P.cur.k != TOK_WORD){ skip_line(&P); continue; }
          char rm[64]; memset(rm, 0, sizeof(rm));
          strncpy(rm, P.cur.s, sizeof(rm)-1);

          next(&P);
          if(is(&P, TOK_WORD, "in")){
            strncpy(n->rmap_in, rm, sizeof(n->rmap_in)-1);
            n->rmap_in[sizeof(n->rmap_in)-1] = 0;
            skip_line(&P);
            continue;
          }
          if(is(&P, TOK_WORD, "out")){
            strncpy(n->rmap_out, rm, sizeof(n->rmap_out)-1);
            n->rmap_out[sizeof(n->rmap_out)-1] = 0;
            skip_line(&P);
            continue;
          }

          skip_line(&P);
          continue;
        }

        if(is(&P, TOK_WORD, "timers")){
          next(&P);
          if(P.cur.k == TOK_WORD){
            uint16_t ka = (uint16_t)atoi(P.cur.s);
            next(&P);
            if(P.cur.k == TOK_WORD){
              uint16_t hold = (uint16_t)atoi(P.cur.s);
              n->keepalive = ka;
              n->hold_time = hold;
            }
          }
          skip_line(&P);
          continue;
        }

        if(is(&P, TOK_WORD, "route-reflector-client")){
          n->is_rr_client = 1;
          skip_line(&P);
          continue;
        }

        if(is(&P, TOK_WORD, "activate")){
          set_neighbor_activate_by_af(&P, n);
          skip_line(&P);
          continue;
        }

        skip_line(&P);
        continue;
      }

      // network <prefix>
      if(is(&P, TOK_WORD, "network")){
        next(&P);
        if(P.cur.k == TOK_WORD){
          if(P.af_ctx == 1){
            // IPv4 global unicast
            struct in_addr pfx;
            uint8_t plen;
            if(parse_prefix4(P.cur.s, &pfx, &plen) == 0){
              if(out->network_count < (int)(sizeof(out->networks)/sizeof(out->networks[0]))){
                out->networks[out->network_count].af = 1;
                out->networks[out->network_count].plen = plen;
                out->networks[out->network_count].prefix.addr4 = pfx;
                out->networks[out->network_count].vrf_name[0] = 0;
                out->network_count++;
              }
            }
          }
          else if(P.af_ctx == 2){
            // IPv6 global unicast
            struct in6_addr pfx;
            int plen;
            if(parse_prefix6(P.cur.s, &pfx, &plen) == 0){
              if(out->network_count < (int)(sizeof(out->networks)/sizeof(out->networks[0]))){
                out->networks[out->network_count].af = 2;
                out->networks[out->network_count].plen = (uint8_t)plen;
                out->networks[out->network_count].prefix.addr6 = pfx;
                out->networks[out->network_count].vrf_name[0] = 0;
                out->network_count++;
              }
            }
          }
          else if(P.af_ctx == 3){
            // VPNv4
            struct in_addr pfx;
            uint8_t plen;
            if(parse_prefix4(P.cur.s, &pfx, &plen) == 0){
              if(out->network_count < (int)(sizeof(out->networks)/sizeof(out->networks[0]))){
                out->networks[out->network_count].af = 3;
                out->networks[out->network_count].plen = plen;
                out->networks[out->network_count].prefix.addr4 = pfx;
                if(P.af_vrf_name[0]){
                  strncpy(out->networks[out->network_count].vrf_name,
                          P.af_vrf_name,
                          sizeof(out->networks[out->network_count].vrf_name)-1);
                  out->networks[out->network_count].vrf_name[
                    sizeof(out->networks[out->network_count].vrf_name)-1] = 0;
                } else {
                  out->networks[out->network_count].vrf_name[0] = 0;
                }
                out->network_count++;
              }
            }
          }
        }
        skip_line(&P);
        continue;
      }

      // unknown under router bgp
      skip_line(&P);
      continue;
    }

    // outside router bgp
    skip_line(&P);
  }

  cfg_lx_close(P.lx);
  fclose(f);

  if(out->params.asn == 0){
    log_msg(BGP_LOG_ERROR, "config missing 'router bgp <asn>'");
    return -1;
  }

  if(out->params.router_id.s_addr == 0){
    inet_aton("0.0.0.0", &out->params.router_id);
  }

  return 0;
}
