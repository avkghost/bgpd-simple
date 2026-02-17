// src/cli.c
// VTY control-plane CLI over a UNIX-domain socket.
// Clients connect with:  nc -U /var/run/bgpd.sock

#include "bgp/cli.h"
#include "bgp/core.h"
#include "bgp/peer.h"
#include "bgp/rib.h"
#include "bgp/attrs.h"
#include "bgp/netlink.h"
#include "bgp/fsm.h"
#include "bgp/event.h"
#include "bgp/log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>

/* MARK: --- Constants --- */

#define CLI_SOCKPATH_MAX 108  /* sizeof(sun_path) on Linux */
#define CLI_RX_MAX       256
#define CLI_TX_MAX       8192
#define CLI_MAX_CLIENTS  8
#define CLI_PROMPT       "bgpd# "

/* MARK: --- Types --- */

typedef struct cli_client {
  int         fd;
  char        rxbuf[CLI_RX_MAX];
  size_t      rxlen;
} cli_client_t;

/* Module-level state — a single singleton is acceptable for a CLI listener. */
static struct {
  int          listen_fd;
  char         sockpath[CLI_SOCKPATH_MAX];
  bgp_core_t*  core;
  event_loop_t* loop;
  cli_client_t clients[CLI_MAX_CLIENTS];
} g_cli;

/* MARK: --- Helpers --- */

static int cli_send(int fd, const char* buf, size_t len)
{
  while (len > 0) {
    ssize_t n = write(fd, buf, len);
    if (n < 0) {
      if (errno == EINTR) continue;
      return -1;
    }
    buf += (size_t)n;
    len -= (size_t)n;
  }
  return 0;
}

static int cli_printf(int fd, const char* fmt, ...)
    __attribute__((format(printf, 2, 3)));

static int cli_printf(int fd, const char* fmt, ...)
{
  char buf[CLI_TX_MAX];
  va_list ap;
  va_start(ap, fmt);
  int n = vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  if (n <= 0) return 0;
  return cli_send(fd, buf, (size_t)n);
}

/* MARK: --- Command handlers --- */

/* ── RIB display helper ─────────────────────────────────────────────── */

static void print_rib4(int fd, const rib4_t* rib)
{
  if (rib->entry_count == 0) {
    cli_printf(fd, "  (empty)\n");
    return;
  }

  cli_printf(fd,
    "   %-19s %-16s %6s %6s  %s\n",
    "Network", "Next Hop", "Metric", "LocPrf", "Path");

  for (int i = 0; i < rib->entry_count; i++) {
    const rib_entry4_t* e = &rib->entries[i];
    if (e->path_count == 0) continue;

    char pfxbuf[24];
    snprintf(pfxbuf, sizeof(pfxbuf), "%s/%u",
             inet_ntoa(e->pfx.pfx), e->pfx.plen);

    for (int j = 0; j < e->path_count; j++) {
      const rib_path4_t* path = &e->paths[j];
      char valid  = (e->best_index >= 0) ? '*' : ' ';
      char best   = (j == e->best_index) ? '>' : ' ';
      char origin = (path->attrs.origin == 0) ? 'i'
                  : (path->attrs.origin == 1) ? 'e' : '?';

      char nh_buf[INET_ADDRSTRLEN];
      if (path->attrs.has_next_hop)
        inet_ntop(AF_INET, &path->attrs.next_hop, nh_buf, sizeof(nh_buf));
      else if (path->from == NULL)
        snprintf(nh_buf, sizeof(nh_buf), "0.0.0.0");  /* static */
      else
        snprintf(nh_buf, sizeof(nh_buf), "?");

      uint32_t med   = path->attrs.has_med        ? path->attrs.med        : 0;
      uint32_t locpf = path->attrs.has_local_pref ? path->attrs.local_pref : 100;

      /* peer address or "static" label */
      char peer_buf[INET_ADDRSTRLEN + 8];
      if (path->from)
        inet_ntop(AF_INET, &path->from->addr, peer_buf, sizeof(peer_buf));
      else
        snprintf(peer_buf, sizeof(peer_buf), "static");

      cli_printf(fd, "%c%c %-19s %-16s %6u %6u  ",
                 valid, best, pfxbuf, nh_buf, med, locpf);

      for (int k = 0; k < path->attrs.as_path_len; k++)
        cli_printf(fd, "%u ", path->attrs.as_path[k]);

      cli_printf(fd, "%c  [via %s]\n", origin, peer_buf);
    }
  }
}

/** show route — global IPv4 RIB */
static void cmd_show_route(int fd, bgp_core_t* c)
{
  cli_printf(fd, "\nGlobal IPv4 RIB (%d entries):\n", c->rib.entry_count);
  cli_printf(fd, "Status: * valid, > best  Origin: i IGP, e EGP, ? incomplete\n\n");
  print_rib4(fd, &c->rib);
  cli_printf(fd, "\n");
}

/** show route vrf <name> — per-VRF IPv4 RIB */
static void cmd_show_route_vrf(int fd, bgp_core_t* c, const char* name)
{
  for (int i = 0; i < c->vrf_inst_count; i++) {
    const vrf_instance_t* vi = &c->vrf_inst[i];
    if (name && name[0] && strcasecmp(vi->cfg.name, name) != 0) continue;

    cli_printf(fd, "\nVRF %s IPv4 RIB (%d entries):\n",
               vi->cfg.name, vi->rib4.entry_count);
    cli_printf(fd, "Status: * valid, > best  Origin: i IGP, e EGP, ? incomplete\n\n");
    print_rib4(fd, &vi->rib4);
    cli_printf(fd, "\n");
  }
}

/* ── Route injection helpers ────────────────────────────────────────── */

/*
 * Parse "A.B.C.D/LEN" into pfx + plen.
 * Returns 0 on success, -1 on parse error.
 */
static int parse_prefix(const char* s, struct in_addr* pfx, uint8_t* plen)
{
  char buf[32];
  const char* slash = strchr(s, '/');
  if (!slash) return -1;
  size_t hlen = (size_t)(slash - s);
  if (hlen == 0 || hlen >= sizeof(buf)) return -1;
  memcpy(buf, s, hlen);
  buf[hlen] = '\0';
  if (inet_aton(buf, pfx) == 0) return -1;
  char* end;
  long len = strtol(slash + 1, &end, 10);
  if (end == slash + 1 || *end != '\0' || len < 0 || len > 32) return -1;
  *plen = (uint8_t)len;
  return 0;
}

/** set route <prefix>/<len> <nexthop> — inject a static route into the global RIB */
static void cmd_set_route(int fd, bgp_core_t* c, const char* args)
{
  /* args = "<prefix>/<len> <nexthop>" */
  char pfx_str[32], nh_str[32];
  if (sscanf(args, "%31s %31s", pfx_str, nh_str) != 2) {
    cli_printf(fd, "%% Usage: set route <prefix>/<len> <nexthop>\n");
    return;
  }

  struct in_addr pfx, nh;
  uint8_t plen;
  if (parse_prefix(pfx_str, &pfx, &plen) < 0) {
    cli_printf(fd, "%% Invalid prefix: %s\n", pfx_str);
    return;
  }
  if (inet_aton(nh_str, &nh) == 0) {
    cli_printf(fd, "%% Invalid nexthop: %s\n", nh_str);
    return;
  }

  bgp_attrs_t a;
  attrs_init(&a);
  a.origin        = 0; /* IGP */
  a.has_next_hop  = true;
  a.next_hop      = nh;
  a.has_local_pref = true;
  a.local_pref    = 100;

  /* from == NULL marks this as a static/locally-injected route */
  rib4_add_or_replace(&c->rib, NULL, pfx, plen, &a);

  int ei = rib4_find_entry(&c->rib, pfx, plen);
  if (ei >= 0) rib4_recompute_best(&c->rib, ei);

  cli_printf(fd, "Static route %s via %s added to global RIB.\n",
             pfx_str, nh_str);
}

/** no route <prefix>/<len> — remove a static route from the global RIB */
static void cmd_no_route(int fd, bgp_core_t* c, const char* args)
{
  char pfx_str[32];
  if (sscanf(args, "%31s", pfx_str) != 1) {
    cli_printf(fd, "%% Usage: no route <prefix>/<len>\n");
    return;
  }

  struct in_addr pfx;
  uint8_t plen;
  if (parse_prefix(pfx_str, &pfx, &plen) < 0) {
    cli_printf(fd, "%% Invalid prefix: %s\n", pfx_str);
    return;
  }

  int ei = rib4_find_entry(&c->rib, pfx, plen);
  if (ei < 0) {
    cli_printf(fd, "%% Route %s not found in RIB.\n", pfx_str);
    return;
  }

  /* Remove only the static path (from == NULL) */
  rib4_withdraw(&c->rib, NULL, pfx, plen);
  ei = rib4_find_entry(&c->rib, pfx, plen);
  if (ei >= 0) rib4_recompute_best(&c->rib, ei);

  cli_printf(fd, "Static route %s removed from global RIB.\n", pfx_str);
}

/* ── System route commands ──────────────────────────────────────────── */

/* Translate Linux RTPROT_* code to a human-readable string. */
static const char* proto_str(uint8_t proto)
{
  switch (proto) {
    case 0:   return "unspec";
    case 2:   return "kernel";
    case 3:   return "boot";
    case 4:   return "static";
    case 8:   return "gated";
    case 12:  return "ospf";
    case 13:  return "bgp";
    case 16:  return "isis";
    case 42:  return "babel";
    case 186: return "bgp";   /* some kernels use 186 */
    default:  return "other";
  }
}

/* Callback used by cmd_show_route_system — prints one route per line. */
typedef struct { int fd; int count; } show_sys_ctx_t;

static int show_sys_cb(const sys_route4_t* r, void* arg)
{
  show_sys_ctx_t* ctx = (show_sys_ctx_t*)arg;

  char dst_buf[INET_ADDRSTRLEN];
  char gw_buf[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &r->dst, dst_buf, sizeof(dst_buf));
  inet_ntop(AF_INET, &r->gw,  gw_buf,  sizeof(gw_buf));

  char pfxbuf[24];
  snprintf(pfxbuf, sizeof(pfxbuf), "%s/%u", dst_buf, r->plen);

  char table_buf[12];
  if (r->table)
    snprintf(table_buf, sizeof(table_buf), "%u", r->table);
  else
    snprintf(table_buf, sizeof(table_buf), "-");

  cli_printf(ctx->fd, "  %-20s %-16s %-8s %-7s %-7s %s\n",
             pfxbuf,
             r->gw.s_addr ? gw_buf : "direct",
             r->ifname[0] ? r->ifname : "-",
             table_buf,
             proto_str(r->proto),
             r->metric ? "" : "");
  ctx->count++;
  return 0;
}

/** show route system — dump kernel IPv4 routing table */
static void cmd_show_route_system(int fd)
{
  cli_printf(fd, "\nSystem IPv4 routes (kernel FIB):\n\n");
  cli_printf(fd, "  %-20s %-16s %-8s %-7s %-7s\n",
             "Destination", "Gateway", "Iface", "Table", "Proto");
  cli_printf(fd, "  %-20s %-16s %-8s %-7s %-7s\n",
             "--------------------", "----------------",
             "--------", "-------", "-------");

  show_sys_ctx_t ctx = { .fd = fd, .count = 0 };
  if (nl_route_dump_v4(show_sys_cb, &ctx) < 0) {
    cli_printf(fd, "  (error reading system routes)\n");
  } else if (ctx.count == 0) {
    cli_printf(fd, "  (no routes)\n");
  }
  cli_printf(fd, "\n");
}

/** set system route <prefix>/<len> <nexthop> [table <id>]
 *  Installs a route into the kernel FIB via nl_route_replace_v4. */
static void cmd_set_system_route(int fd, const char* args)
{
  char pfx_str[32], nh_str[32];
  if (sscanf(args, "%31s %31s", pfx_str, nh_str) != 2) {
    cli_printf(fd, "%% Usage: set system route <prefix>/<len> <nexthop> [table <id>]\n");
    return;
  }

  struct in_addr pfx, nh;
  uint8_t plen;
  if (parse_prefix(pfx_str, &pfx, &plen) < 0) {
    cli_printf(fd, "%% Invalid prefix: %s\n", pfx_str);
    return;
  }
  if (inet_aton(nh_str, &nh) == 0) {
    cli_printf(fd, "%% Invalid nexthop: %s\n", nh_str);
    return;
  }

  /* Optional "table <id>" suffix */
  int table = 254; /* RT_TABLE_MAIN */
  const char* tp = strstr(args, "table ");
  if (tp) {
    long t = strtol(tp + 6, NULL, 10);
    if (t > 0 && t < 256) table = (int)t;
  }

  if (nl_route_replace_v4(pfx, plen, nh, table) < 0) {
    cli_printf(fd, "%% Failed to install system route %s via %s (table %d): %s\n",
               pfx_str, nh_str, table, strerror(errno));
    return;
  }
  cli_printf(fd, "System route %s via %s (table %d) installed.\n",
             pfx_str, nh_str, table);
}

/** no system route <prefix>/<len> [table <id>]
 *  Removes a route from the kernel FIB via nl_route_delete_v4. */
static void cmd_no_system_route(int fd, const char* args)
{
  char pfx_str[32];
  if (sscanf(args, "%31s", pfx_str) != 1) {
    cli_printf(fd, "%% Usage: no system route <prefix>/<len> [table <id>]\n");
    return;
  }

  struct in_addr pfx;
  uint8_t plen;
  if (parse_prefix(pfx_str, &pfx, &plen) < 0) {
    cli_printf(fd, "%% Invalid prefix: %s\n", pfx_str);
    return;
  }

  int table = 254;
  const char* tp = strstr(args, "table ");
  if (tp) {
    long t = strtol(tp + 6, NULL, 10);
    if (t > 0 && t < 256) table = (int)t;
  }

  if (nl_route_delete_v4(pfx, plen, table) < 0) {
    cli_printf(fd, "%% Failed to remove system route %s (table %d): %s\n",
               pfx_str, table, strerror(errno));
    return;
  }
  cli_printf(fd, "System route %s (table %d) removed.\n", pfx_str, table);
}

/** apply routes [table <id>]
 *  Push every best-path from the global BGP RIB into the kernel FIB. */
static void cmd_apply_routes(int fd, bgp_core_t* c, const char* args)
{
  int table = c->fib_table ? c->fib_table : 254; /* RT_TABLE_MAIN */
  if (args && args[0]) {
    const char* tp = strstr(args, "table ");
    if (tp) {
      long t = strtol(tp + 6, NULL, 10);
      if (t > 0 && t < 256) table = (int)t;
    }
  }

  int installed = 0, skipped = 0;
  for (int i = 0; i < c->rib.entry_count; i++) {
    const rib_entry4_t* e = &c->rib.entries[i];
    if (e->best_index < 0) continue;

    const rib_path4_t* best = &e->paths[e->best_index];
    if (!best->attrs.has_next_hop) { skipped++; continue; }

    if (nl_route_replace_v4(e->pfx.pfx, e->pfx.plen,
                             best->attrs.next_hop, table) == 0)
      installed++;
    else
      skipped++;
  }

  cli_printf(fd, "Applied %d route(s) to kernel table %d (%d skipped).\n",
             installed, table, skipped);
}

/** show bgp summary — one line per configured peer */
static void cmd_show_bgp_summary(int fd, bgp_core_t* c)
{
  cli_printf(fd, "\nBGP router identifier %s, local AS number %u\n",
             inet_ntoa(c->router_id), c->local_asn);
  cli_printf(fd, "\nNeighbor        V   AS    MsgRcvd  MsgSent  State\n");
  cli_printf(fd, "%-15s %-3s %-5s %-8s %-8s %s\n",
             "-----------", "--", "-----", "-------", "-------", "-----");

  for (int i = 0; i < c->peer_count; i++) {
    const bgp_peer_t* p = c->peers[i];
    if (!p) continue;
    cli_printf(fd, "%-15s  4  %-5u %-8s %-8s %s\n",
               inet_ntoa(p->addr),
               p->remote_asn_cfg,
               "-", "-",
               bgp_state_str(p->st));
  }
  cli_printf(fd, "\n");
}

/** show ip bgp — IPv4 unicast RIB dump */
static void cmd_show_ip_bgp(int fd, bgp_core_t* c)
{
  cli_printf(fd, "\nStatus codes: * valid, > best\n");
  cli_printf(fd, "Origin codes:  i - IGP, e - EGP, ? - incomplete\n\n");
  cli_printf(fd, "   Network          Next Hop         Metric LocPrf Weight Path\n");

  for (int i = 0; i < c->rib.entry_count; i++) {
    const rib_entry4_t* e = &c->rib.entries[i];
    if (e->path_count == 0) continue;

    char pfxbuf[32];
    snprintf(pfxbuf, sizeof(pfxbuf), "%s/%u",
             inet_ntoa(e->pfx.pfx), e->pfx.plen);

    for (int j = 0; j < e->path_count; j++) {
      const rib_path4_t* path = &e->paths[j];
      char valid = (e->best_index >= 0) ? '*' : ' ';
      char best  = (j == e->best_index) ? '>' : ' ';
      char origin_ch = (path->attrs.origin == 0) ? 'i'
                     : (path->attrs.origin == 1) ? 'e' : '?';

      char nh_buf[INET_ADDRSTRLEN];
      if (path->attrs.has_next_hop)
        inet_ntop(AF_INET, &path->attrs.next_hop, nh_buf, sizeof(nh_buf));
      else
        snprintf(nh_buf, sizeof(nh_buf), "0.0.0.0");

      uint32_t med   = path->attrs.has_med       ? path->attrs.med       : 0;
      uint32_t locpf = path->attrs.has_local_pref ? path->attrs.local_pref : 100;

      cli_printf(fd, "%c%c %-18s %-16s %6u %6u      0 ",
                 valid, best, pfxbuf, nh_buf, med, locpf);

      /* AS_PATH */
      for (int k = 0; k < path->attrs.as_path_len; k++) {
        cli_printf(fd, "%u ", path->attrs.as_path[k]);
      }
      cli_printf(fd, "%c\n", origin_ch);
    }
  }
  cli_printf(fd, "\n");
}

/** show bgp neighbors — verbose per-peer state */
static void cmd_show_bgp_neighbors(int fd, bgp_core_t* c)
{
  for (int i = 0; i < c->peer_count; i++) {
    const bgp_peer_t* p = c->peers[i];
    if (!p) continue;

    cli_printf(fd,
      "\nBGP neighbor is %s, remote AS %u\n"
      "  Description: %s\n"
      "  BGP state = %s\n"
      "  Local AS = %u, Hold time %u, Keepalive %u\n"
      "  Negotiated hold time: %u\n"
      "  Capabilities:\n"
      "    IPv4 Unicast:  %s\n"
      "    IPv6 Unicast:  %s\n"
      "    VPNv4:         %s\n"
      "    EVPN:          %s\n"
      "    VPLS:          %s\n"
      "    Route-Refresh: %s\n"
      "    4-byte ASN:    %s\n"
      "    Graceful-Rst:  %s (restart-time %us)\n"
      "  Route-reflector client: %s\n",
      inet_ntoa(p->addr),
      p->remote_asn_cfg,
      p->description[0] ? p->description : "(none)",
      bgp_state_str(p->st),
      p->local_asn, p->local_hold, p->local_keepalive,
      p->negotiated_hold,
      p->caps.mp_ipv4u   ? "advertised and received" : "not negotiated",
      p->caps.mp_ipv6u   ? "advertised and received" : "not negotiated",
      p->caps.mp_vpnv4   ? "advertised and received" : "not negotiated",
      p->caps.mp_evpn    ? "advertised and received" : "not negotiated",
      p->caps.mp_vpls    ? "advertised and received" : "not negotiated",
      p->caps.route_refresh  ? "advertised and received" : "not negotiated",
      p->caps.as4            ? "advertised and received" : "not negotiated",
      p->caps.graceful_restart ? "advertised and received" : "not negotiated",
      p->caps.gr_time,
      p->is_rr_client ? "yes" : "no");
  }
  cli_printf(fd, "\n");
}

/** show vrf [<name>] — VRF instance table */
static void cmd_show_vrf(int fd, bgp_core_t* c, const char* name)
{
  if (c->vrf_inst_count == 0) {
    cli_printf(fd, "\nNo VRF instances configured.\n\n");
    return;
  }

  cli_printf(fd,
    "\n%-20s %-14s %-14s %-6s %-20s\n",
    "VRF", "RD", "Export-RT(s)", "VNI", "Bridge");
  cli_printf(fd,
    "%-20s %-14s %-14s %-6s %-20s\n",
    "--------------------", "--------------",
    "--------------", "------", "--------------------");

  for (int i = 0; i < c->vrf_inst_count; i++) {
    const vrf_instance_t* vi = &c->vrf_inst[i];
    const vrf_t*          v  = &vi->cfg;

    /* Optional name filter */
    if (name && name[0] && strcasecmp(v->name, name) != 0) continue;

    /* Format RD as ASN:NN */
    char rd_buf[32];
    if (v->rd.asn || v->rd.val)
      snprintf(rd_buf, sizeof(rd_buf), "%u:%u", v->rd.asn, v->rd.val);
    else
      snprintf(rd_buf, sizeof(rd_buf), "(none)");

    /* Format export RTs — show first one inline, rest on continuation lines */
    char rt_buf[32];
    if (v->export_count > 0)
      snprintf(rt_buf, sizeof(rt_buf), "%u:%u",
               v->export_rts[0].asn, v->export_rts[0].val);
    else
      snprintf(rt_buf, sizeof(rt_buf), "(none)");

    char vni_buf[16];
    if (v->vni)
      snprintf(vni_buf, sizeof(vni_buf), "%u", v->vni);
    else
      snprintf(vni_buf, sizeof(vni_buf), "-");

    cli_printf(fd, "%-20s %-14s %-14s %-6s %-20s\n",
               v->name, rd_buf, rt_buf, vni_buf,
               v->bridge[0] ? v->bridge : "-");

    /* Additional export RTs on continuation lines */
    for (int r = 1; r < v->export_count; r++) {
      snprintf(rt_buf, sizeof(rt_buf), "%u:%u",
               v->export_rts[r].asn, v->export_rts[r].val);
      cli_printf(fd, "%-20s %-14s %-14s\n", "", "", rt_buf);
    }

    /* Import RTs */
    if (v->import_count > 0) {
      cli_printf(fd, "  Import-RT:");
      for (int r = 0; r < v->import_count; r++)
        cli_printf(fd, " %u:%u", v->import_rts[r].asn, v->import_rts[r].val);
      cli_printf(fd, "\n");
    }

    /* IPv4 RIB entry count for this VRF */
    cli_printf(fd, "  RIB entries: %d\n", vi->rib4.entry_count);
  }
  cli_printf(fd, "\n");
}

/** clear bgp <ip> — reset a specific peer session */
static void cmd_clear_bgp_peer(int fd, bgp_core_t* c, const char* addr_str)
{
  struct in_addr target;
  if (inet_aton(addr_str, &target) == 0) {
    cli_printf(fd, "%% Invalid address: %s\n", addr_str);
    return;
  }

  for (int i = 0; i < c->peer_count; i++) {
    bgp_peer_t* p = c->peers[i];
    if (!p) continue;
    if (p->addr.s_addr == target.s_addr) {
      cli_printf(fd, "Resetting BGP session with %s\n", addr_str);
      bgp_fsm_event(p, BGP_EVT_STOP);
      bgp_fsm_event(p, BGP_EVT_START);
      return;
    }
  }
  cli_printf(fd, "%% Neighbor %s not found\n", addr_str);
}

/** clear bgp all — reset all peer sessions */
static void cmd_clear_bgp_all(int fd, bgp_core_t* c)
{
  cli_printf(fd, "Resetting all BGP sessions\n");
  for (int i = 0; i < c->peer_count; i++) {
    bgp_peer_t* p = c->peers[i];
    if (!p) continue;
    bgp_fsm_event(p, BGP_EVT_STOP);
    bgp_fsm_event(p, BGP_EVT_START);
  }
}

/* MARK: --- Command dispatcher --- */

/**
 * @brief Parse and execute one command line from a VTY client.
 *
 * @return 0 to keep connection open, -1 to close it.
 */
static int cli_dispatch(int fd, bgp_core_t* c, const char* line)
{
  /* Skip leading whitespace */
  while (*line == ' ' || *line == '\t') line++;

  if (strncasecmp(line, "show bgp summary", 16) == 0) {
    cmd_show_bgp_summary(fd, c);
  } else if (strncasecmp(line, "show ip bgp", 11) == 0) {
    cmd_show_ip_bgp(fd, c);
  } else if (strncasecmp(line, "show bgp neighbors", 18) == 0) {
    cmd_show_bgp_neighbors(fd, c);
  } else if (strncasecmp(line, "show route system", 17) == 0) {
    cmd_show_route_system(fd);
  } else if (strncasecmp(line, "show route vrf ", 15) == 0) {
    cmd_show_route_vrf(fd, c, line + 15);
  } else if (strncasecmp(line, "show route vrf", 14) == 0) {
    cmd_show_route_vrf(fd, c, NULL);   /* all VRFs */
  } else if (strncasecmp(line, "show route", 10) == 0) {
    cmd_show_route(fd, c);
  } else if (strncasecmp(line, "show vrf ", 9) == 0) {
    cmd_show_vrf(fd, c, line + 9);
  } else if (strncasecmp(line, "show vrf", 8) == 0) {
    cmd_show_vrf(fd, c, NULL);
  } else if (strncasecmp(line, "apply routes", 12) == 0) {
    cmd_apply_routes(fd, c, line + 12);
  } else if (strncasecmp(line, "set system route ", 17) == 0) {
    cmd_set_system_route(fd, line + 17);
  } else if (strncasecmp(line, "no system route ", 16) == 0) {
    cmd_no_system_route(fd, line + 16);
  } else if (strncasecmp(line, "set route ", 10) == 0) {
    cmd_set_route(fd, c, line + 10);
  } else if (strncasecmp(line, "no route ", 9) == 0) {
    cmd_no_route(fd, c, line + 9);
  } else if (strncasecmp(line, "clear bgp all", 13) == 0) {
    cmd_clear_bgp_all(fd, c);
  } else if (strncasecmp(line, "clear bgp ", 10) == 0) {
    cmd_clear_bgp_peer(fd, c, line + 10);
  } else if (strncasecmp(line, "exit", 4) == 0 ||
             strncasecmp(line, "quit", 4) == 0) {
    cli_send(fd, "Bye.\n", 5);
    return -1; /* signal close */
  } else if (*line == '\0' || *line == '\r' || *line == '\n') {
    /* empty line — just re-prompt */
  } else {
    cli_printf(fd, "%% Unknown command: %s\n", line);
    cli_printf(fd,
      "Available commands:\n"
      "  show bgp summary\n"
      "  show ip bgp\n"
      "  show bgp neighbors\n"
      "  show route\n"
      "  show route system\n"
      "  show route vrf [<name>]\n"
      "  show vrf [<name>]\n"
      "  set route <prefix>/<len> <nexthop>\n"
      "  no route <prefix>/<len>\n"
      "  set system route <prefix>/<len> <nexthop> [table <id>]\n"
      "  no system route <prefix>/<len> [table <id>]\n"
      "  apply routes [table <id>]\n"
      "  clear bgp <neighbor-ip>\n"
      "  clear bgp all\n"
      "  exit | quit\n");
  }

  cli_send(fd, CLI_PROMPT, sizeof(CLI_PROMPT) - 1);
  return 0;
}

/* MARK: --- I/O callbacks --- */

static cli_client_t* find_client_by_fd(int fd)
{
  for (int i = 0; i < CLI_MAX_CLIENTS; i++) {
    if (g_cli.clients[i].fd == fd) return &g_cli.clients[i];
  }
  return NULL;
}

static cli_client_t* alloc_client(int fd)
{
  for (int i = 0; i < CLI_MAX_CLIENTS; i++) {
    if (g_cli.clients[i].fd < 0) {
      g_cli.clients[i].fd    = fd;
      g_cli.clients[i].rxlen = 0;
      return &g_cli.clients[i];
    }
  }
  return NULL;
}

static void free_client(cli_client_t* cl)
{
  if (!cl) return;
  if (cl->fd >= 0) {
    (void)ev_del_fd(g_cli.loop, cl->fd);
    close(cl->fd);
    cl->fd = -1;
  }
  cl->rxlen = 0;
}

static void on_cli_client_io(int fd, uint32_t events, void* arg)
{
  (void)events;
  (void)arg;
  cli_client_t* cl = find_client_by_fd(fd);
  if (!cl) return;

  for (;;) {
    size_t space = sizeof(cl->rxbuf) - cl->rxlen - 1;
    if (space == 0) {
      /* Buffer full — discard and reset */
      cl->rxlen = 0;
      break;
    }

    ssize_t n = read(fd, cl->rxbuf + cl->rxlen, space);
    if (n < 0) {
      if (errno == EINTR) continue;
      if (errno == EAGAIN || errno == EWOULDBLOCK) break;
      free_client(cl);
      return;
    }
    if (n == 0) {
      /* EOF */
      free_client(cl);
      return;
    }
    cl->rxlen += (size_t)n;
    cl->rxbuf[cl->rxlen] = '\0';

    /* Process complete newline-terminated lines */
    char* start = cl->rxbuf;
    char* nl;
    while ((nl = strchr(start, '\n')) != NULL) {
      *nl = '\0';
      /* Strip trailing \r */
      size_t slen = strlen(start);
      if (slen > 0 && start[slen - 1] == '\r') start[slen - 1] = '\0';

      if (cli_dispatch(fd, g_cli.core, start) < 0) {
        free_client(cl);
        return;
      }
      start = nl + 1;
    }

    /* Move remaining partial line to front */
    size_t rem = (size_t)((cl->rxbuf + cl->rxlen) - start);
    if (rem > 0 && start != cl->rxbuf) {
      memmove(cl->rxbuf, start, rem);
    }
    cl->rxlen = rem;
    cl->rxbuf[cl->rxlen] = '\0';
  }
}

static void on_cli_accept(int fd, uint32_t events, void* arg)
{
  (void)events;
  (void)arg;

  int cfd = accept(fd, NULL, NULL);
  if (cfd < 0) return;

  /* Set non-blocking */
  int fl = fcntl(cfd, F_GETFL, 0);
  if (fl >= 0) (void)fcntl(cfd, F_SETFL, fl | O_NONBLOCK);

  cli_client_t* cl = alloc_client(cfd);
  if (!cl) {
    close(cfd);
    return;
  }

  if (ev_add_fd(g_cli.loop, cfd, EV_READ, on_cli_client_io, NULL) < 0) {
    free_client(cl);
    return;
  }

  cli_send(cfd,
    "\nWelcome to bgpd VTY\n"
    "Type 'exit' or 'quit' to disconnect.\n"
    CLI_PROMPT,
    strlen("\nWelcome to bgpd VTY\n"
           "Type 'exit' or 'quit' to disconnect.\n"
           CLI_PROMPT));
}

/* MARK: --- Public API --- */

int cli_start(bgp_core_t* c, event_loop_t* loop, const char* sockpath)
{
  if (!c || !loop || !sockpath) return -1;

  /* Initialise client slots */
  for (int i = 0; i < CLI_MAX_CLIENTS; i++) {
    g_cli.clients[i].fd    = -1;
    g_cli.clients[i].rxlen = 0;
  }

  g_cli.core       = c;
  g_cli.loop       = loop;
  g_cli.listen_fd  = -1;
  strncpy(g_cli.sockpath, sockpath, sizeof(g_cli.sockpath) - 1);
  g_cli.sockpath[sizeof(g_cli.sockpath) - 1] = '\0';

  /* Remove any stale socket file */
  (void)unlink(sockpath);

  int lfd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (lfd < 0) {
    log_msg(BGP_LOG_ERROR, "cli_start: socket(AF_UNIX): %s", strerror(errno));
    return -1;
  }

  /* FD_CLOEXEC */
  int fl = fcntl(lfd, F_GETFD, 0);
  if (fl >= 0) (void)fcntl(lfd, F_SETFD, fl | FD_CLOEXEC);

  struct sockaddr_un sa;
  memset(&sa, 0, sizeof(sa));
  sa.sun_family = AF_UNIX;
  strncpy(sa.sun_path, sockpath, sizeof(sa.sun_path) - 1);

  if (bind(lfd, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
    log_msg(BGP_LOG_ERROR, "cli_start: bind(%s): %s", sockpath, strerror(errno));
    close(lfd);
    return -1;
  }

  if (listen(lfd, 4) < 0) {
    log_msg(BGP_LOG_ERROR, "cli_start: listen: %s", strerror(errno));
    close(lfd);
    (void)unlink(sockpath);
    return -1;
  }

  /* Non-blocking */
  fl = fcntl(lfd, F_GETFL, 0);
  if (fl >= 0) (void)fcntl(lfd, F_SETFL, fl | O_NONBLOCK);

  if (ev_add_fd(loop, lfd, EV_READ, on_cli_accept, NULL) < 0) {
    log_msg(BGP_LOG_ERROR, "cli_start: ev_add_fd failed");
    close(lfd);
    (void)unlink(sockpath);
    return -1;
  }

  g_cli.listen_fd = lfd;
  log_msg(BGP_LOG_INFO, "VTY CLI listening on %s", sockpath);
  return 0;
}

void cli_stop(void)
{
  for (int i = 0; i < CLI_MAX_CLIENTS; i++) {
    if (g_cli.clients[i].fd >= 0) free_client(&g_cli.clients[i]);
  }
  if (g_cli.listen_fd >= 0) {
    if (g_cli.loop) (void)ev_del_fd(g_cli.loop, g_cli.listen_fd);
    close(g_cli.listen_fd);
    g_cli.listen_fd = -1;
  }
  if (g_cli.sockpath[0]) {
    (void)unlink(g_cli.sockpath);
    g_cli.sockpath[0] = '\0';
  }
}
