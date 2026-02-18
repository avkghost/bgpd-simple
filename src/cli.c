// src/cli.c
// VTY control-plane CLI over a UNIX-domain socket.
// Clients connect with:  nc -U /tmp/bgpd.sock
//
// The server implements a minimal line editor so that history and tab
// completion work even when clients use raw nc (no PTY).  On connect we
// send TELNET IAC negotiation to put the far end into character-at-a-time
// mode with server-side echo; this is exactly how Cisco IOS / FRR VTY work.

#include "bgp/cli.h"
#include "bgp/core.h"
#include "bgp/peer.h"
#include "bgp/rib.h"
#include "bgp/attrs.h"
#include "bgp/netlink.h"
#include "bgp/interface.h"
#include "bgp/policy.h"
#include "bgp/fsm.h"
#include "bgp/event.h"
#include "bgp/log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netdb.h>

/* MARK: --- Constants --- */

#define CLI_SOCKPATH_MAX 108  /* sizeof(sun_path) on Linux */
#define CLI_TX_MAX       8192
#define CLI_MAX_CLIENTS  8
#define CLI_PROMPT       "bgpd# "

/* Line editor limits */
#define CLI_LINE_MAX     256
#define CLI_HIST_MAX     20

/* TELNET option codes */
#define IAC   255
#define WILL  251
#define WONT  252
#define DO    253
#define DONT  254
#define SB    250
#define SE    240
#define OPT_ECHO      1
#define OPT_SGA       3   /* suppress go-ahead */
#define OPT_LINEMODE  34

/* MARK: --- Types --- */

typedef enum {
  MODE_EXEC,           /* Normal command execution */
  MODE_INTERFACE,      /* interface <name> configuration mode */
  MODE_ROUTER_BGP,     /* router bgp configuration mode */
  MODE_ADDRESS_FAMILY  /* address-family configuration mode */
} cli_mode_t;

typedef struct cli_client {
  int    fd;

  /* ── Line editor ─────────────────────────────────────────────────── */
  char   line[CLI_LINE_MAX];   /* editing buffer (not NUL-terminated during edit) */
  int    line_len;             /* number of chars in buffer */

  /* Escape-sequence parser: 0=normal 1=got-ESC 2=got-ESC-[ */
  int    esc_state;
  /* Collect SB (sub-negotiation) bytes so we skip them safely */
  int    in_sb;

  /* ── History ring buffer ─────────────────────────────────────────── */
  char   history[CLI_HIST_MAX][CLI_LINE_MAX];
  int    hist_count;           /* number of valid entries (0..CLI_HIST_MAX) */
  int    hist_head;            /* index where next entry will be written */
  int    hist_idx;             /* browsing index: -1 = not browsing */
  char   hist_saved[CLI_LINE_MAX]; /* line snapshot taken when browsing starts */

  /* ── Configuration mode ──────────────────────────────────────────── */
  cli_mode_t mode;             /* current mode (EXEC or configuration) */
  char   context_name[64];     /* e.g. "eth0", "65000", "ipv4 unicast" */
  void*  context_obj;          /* pointer to mode-specific context object */
} cli_client_t;

/* Module-level state — a single singleton is acceptable for a CLI listener. */
static struct {
  int          listen_fd;
  char         sockpath[CLI_SOCKPATH_MAX];
  bgp_core_t*  core;
  event_loop_t* loop;
  cli_client_t clients[CLI_MAX_CLIENTS];
} g_cli;

/* MARK: --- Low-level I/O helpers --- */

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

/* MARK: --- Line editor helpers --- */

/* Redraw the current editing line after the cursor may have moved.
 * Sends:  \r  <prompt>  <line-content>
 * (We do not track cursor sub-position — cursor is always at end of line.) */
static void redraw_line(cli_client_t* cl)
{
  /* Move to column 0, print mode-aware prompt, print line content */
  const char* prompt = CLI_PROMPT;
  if (cl->mode == MODE_INTERFACE) {
    cli_printf(cl->fd, "\rbgpd(%s)# %.*s", cl->context_name, cl->line_len, cl->line);
  } else if (cl->mode == MODE_ROUTER_BGP) {
    cli_printf(cl->fd, "\rbgpd(bgp)# %.*s", cl->line_len, cl->line);
  } else if (cl->mode == MODE_ADDRESS_FAMILY) {
    cli_printf(cl->fd, "\rbgpd(af)# %.*s", cl->line_len, cl->line);
  } else {
    cli_printf(cl->fd, "\r%s%.*s", prompt, cl->line_len, cl->line);
  }
  /* Erase any stale characters to the right (in case new line is shorter) */
  cli_send(cl->fd, "\x1b[K", 3);   /* CSI K — erase to end of line */
}

/* Push the current editing buffer into the history ring. */
static void hist_push(cli_client_t* cl)
{
  if (cl->line_len == 0) return;

  /* Avoid duplicate consecutive entries */
  if (cl->hist_count > 0) {
    int prev = (cl->hist_head - 1 + CLI_HIST_MAX) % CLI_HIST_MAX;
    if (strncmp(cl->history[prev], cl->line, (size_t)cl->line_len) == 0
        && cl->history[prev][cl->line_len] == '\0')
      return;
  }

  memcpy(cl->history[cl->hist_head], cl->line, (size_t)cl->line_len);
  cl->history[cl->hist_head][cl->line_len] = '\0';
  cl->hist_head = (cl->hist_head + 1) % CLI_HIST_MAX;
  if (cl->hist_count < CLI_HIST_MAX) cl->hist_count++;
}

/* Navigate to an older history entry (up arrow). */
static void hist_prev(cli_client_t* cl)
{
  if (cl->hist_count == 0) return;

  if (cl->hist_idx < 0) {
    /* Save current edit line before we start browsing */
    memcpy(cl->hist_saved, cl->line, (size_t)cl->line_len);
    cl->hist_saved[cl->line_len] = '\0';
    cl->hist_idx = cl->hist_count - 1;  /* start at most recent */
  } else if (cl->hist_idx > 0) {
    cl->hist_idx--;
  } else {
    return;  /* already at oldest */
  }

  int ring_pos = (cl->hist_head - 1 - cl->hist_idx + CLI_HIST_MAX * 2) % CLI_HIST_MAX;
  const char* entry = cl->history[ring_pos];
  cl->line_len = (int)strlen(entry);
  memcpy(cl->line, entry, (size_t)cl->line_len);
  redraw_line(cl);
}

/* Navigate to a newer history entry (down arrow). */
static void hist_next(cli_client_t* cl)
{
  if (cl->hist_idx < 0) return;  /* not browsing */

  if (cl->hist_idx < cl->hist_count - 1) {
    cl->hist_idx++;
    int ring_pos = (cl->hist_head - 1 - cl->hist_idx + CLI_HIST_MAX * 2) % CLI_HIST_MAX;
    const char* entry = cl->history[ring_pos];
    cl->line_len = (int)strlen(entry);
    memcpy(cl->line, entry, (size_t)cl->line_len);
  } else {
    /* Past the end — restore saved line */
    cl->hist_idx = -1;
    cl->line_len = (int)strlen(cl->hist_saved);
    memcpy(cl->line, cl->hist_saved, (size_t)cl->line_len);
  }
  redraw_line(cl);
}

/* Tab-complete the first verb only.
 * Only attempts completion when the cursor hasn't yet seen a space
 * (i.e., we are still typing the first word). */
static const char* const VERBS[] = {
  "show", "ip", "no", "clear", "apply", "write", "interface", "exit", "quit", NULL
};

static void tab_complete(cli_client_t* cl)
{
  /* Only complete in the first word (no space typed yet) */
  for (int i = 0; i < cl->line_len; i++) {
    if (cl->line[i] == ' ') return;
  }

  /* Collect matches */
  const char* matches[16];
  int  nmatch = 0;

  /* If in interface mode, complete interface subcommands */
  if (cl->mode == MODE_INTERFACE) {
    static const char* const IF_CMDS[] = {
      "ip", "ipv6", "description", "mtu", "shutdown", "no", "exit", NULL
    };
    for (int v = 0; IF_CMDS[v] && nmatch < 16; v++) {
      if (strncasecmp(cl->line, IF_CMDS[v], (size_t)cl->line_len) == 0)
        matches[nmatch++] = IF_CMDS[v];
    }
  } else {
    /* Normal EXEC mode completion */
    for (int v = 0; VERBS[v] && nmatch < 16; v++) {
      if (strncasecmp(cl->line, VERBS[v], (size_t)cl->line_len) == 0)
        matches[nmatch++] = VERBS[v];
    }
  }

  if (nmatch == 0) {
    /* No match — ring the bell */
    cli_send(cl->fd, "\x07", 1);
    return;
  }

  if (nmatch == 1) {
    /* Unique match: complete it and add a trailing space */
    const char* m   = matches[0];
    size_t      mlen = strlen(m);
    size_t      rest = mlen - (size_t)cl->line_len;
    /* Append remaining characters */
    if ((size_t)cl->line_len + rest + 1 < CLI_LINE_MAX) {
      memcpy(cl->line + cl->line_len, m + cl->line_len, rest);
      cl->line_len += (int)rest;
      cl->line[cl->line_len++] = ' ';
      /* Echo only the newly-appended portion */
      cli_send(cl->fd, m + (mlen - rest), rest);
      cli_send(cl->fd, " ", 1);
    }
    return;
  }

  /* Multiple matches — print them below the current line */
  cli_send(cl->fd, "\r\n", 2);
  for (int i = 0; i < nmatch; i++) {
    cli_printf(cl->fd, "  %s\r\n", matches[i]);
  }
  /* Reprint prompt + current partial line */
  if (cl->mode == MODE_INTERFACE) {
    cli_printf(cl->fd, "bgpd(%s)# %.*s", cl->context_name, cl->line_len, cl->line);
  } else {
    cli_printf(cl->fd, CLI_PROMPT "%.*s", cl->line_len, cl->line);
  }
}

/* Process a backspace/DEL character. */
static void do_backspace(cli_client_t* cl)
{
  if (cl->line_len <= 0) return;
  cl->line_len--;
  cli_send(cl->fd, "\b \b", 3);
}

/* Clear the current editing line (Ctrl-C). */
static void do_clear_line(cli_client_t* cl)
{
  cl->line_len  = 0;
  cl->hist_idx  = -1;
  cli_send(cl->fd, "\r\n" CLI_PROMPT, 2 + sizeof(CLI_PROMPT) - 1);
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

static int parse_prefix_v6(const char* s, struct in6_addr* pfx, uint8_t* plen)
{
  char buf[INET6_ADDRSTRLEN + 1];
  const char* slash = strchr(s, '/');
  if (!slash) return -1;
  size_t hlen = (size_t)(slash - s);
  if (hlen == 0 || hlen >= sizeof(buf)) return -1;
  memcpy(buf, s, hlen);
  buf[hlen] = '\0';
  if (inet_pton(AF_INET6, buf, pfx) != 1) return -1;
  char* end;
  long len = strtol(slash + 1, &end, 10);
  if (end == slash + 1 || *end != '\0' || len < 0 || len > 128) return -1;
  *plen = (uint8_t)len;
  return 0;
}

/* ── Route management (RIB + kernel FIB) ───────────────────────────────── */

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

/* Callback used by cmd_show_route_kernel — prints one kernel route per line. */
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

  cli_printf(ctx->fd, "  %-20s %-16s %-8s %-7s %-7s\n",
             pfxbuf,
             r->gw.s_addr ? gw_buf : "direct",
             r->ifname[0] ? r->ifname : "-",
             table_buf,
             proto_str(r->proto));
  ctx->count++;
  return 0;
}

/** show route kernel — dump kernel IPv4 routing table (FIB) */
static void cmd_show_route_kernel(int fd)
{
  cli_printf(fd, "\nKernel IPv4 routes (FIB):\n\n");
  cli_printf(fd, "  %-20s %-16s %-8s %-7s %-7s\n",
             "Destination", "Gateway", "Iface", "Table", "Proto");
  cli_printf(fd, "  %-20s %-16s %-8s %-7s %-7s\n",
             "--------------------", "----------------",
             "--------", "-------", "-------");

  show_sys_ctx_t ctx = { .fd = fd, .count = 0 };
  if (nl_route_dump_v4(show_sys_cb, &ctx) < 0) {
    cli_printf(fd, "  (error reading kernel routes)\n");
  } else if (ctx.count == 0) {
    cli_printf(fd, "  (no routes)\n");
  }
  cli_printf(fd, "\n");
}

/*
 * ip route <prefix>/<len> { via <nexthop> | dev <ifname> }
 *          [via <nexthop>] [dev <ifname>] [table <id>] [kernel]
 *
 * Injects a static route into the BGP RIB and optionally programs the
 * kernel FIB.  The "kernel" keyword forces FIB programming even when only
 * a nexthop is given (it is always done when "dev" is specified).
 *
 * Examples:
 *   ip route 10.0.0.0/8 via 192.168.1.1
 *   ip route 10.0.0.0/8 dev eth0
 *   ip route 10.0.0.0/8 via 192.168.1.1 dev eth0
 *   ip route 0.0.0.0/0 via 192.168.1.1 table 200 kernel
 */
static void cmd_ip_route(int fd, bgp_core_t* c, const char* args)
{
  /* First token must be the prefix */
  char pfx_str[32];
  if (sscanf(args, "%31s", pfx_str) != 1) {
    cli_printf(fd, "%% Usage: ip route <prefix>/<len> [via <nh>] [dev <if>] "
                   "[table <id>] [kernel]\n");
    return;
  }

  struct in_addr pfx;
  uint8_t plen;
  if (parse_prefix(pfx_str, &pfx, &plen) < 0) {
    cli_printf(fd, "%% Invalid prefix: %s\n", pfx_str);
    return;
  }

  /* Scan remaining tokens */
  struct in_addr nh  = {0};
  char   ifname[16]  = {0};
  int    table       = 254; /* RT_TABLE_MAIN */
  bool   do_kernel   = false;

  const char* p = args + strlen(pfx_str);
  while (*p == ' ') p++;

  /* Support legacy positional nexthop: ip route <pfx> <nexthop> */
  {
    struct in_addr maybe;
    char tok[32];
    if (sscanf(p, "%31s", tok) == 1 && inet_aton(tok, &maybe) != 0) {
      nh = maybe;
      p += strlen(tok);
      while (*p == ' ') p++;
    }
  }

  /* Parse keyword arguments */
  while (*p) {
    char kw[32], val[32];
    int consumed = 0;
    if (sscanf(p, "%31s %31s%n", kw, val, &consumed) == 2) {
      if (strcasecmp(kw, "via") == 0) {
        if (inet_aton(val, &nh) == 0) {
          cli_printf(fd, "%% Invalid nexthop: %s\n", val);
          return;
        }
        p += consumed; while (*p == ' ') p++;
        continue;
      }
      if (strcasecmp(kw, "dev") == 0) {
        strncpy(ifname, val, sizeof(ifname) - 1);
        p += consumed; while (*p == ' ') p++;
        continue;
      }
      if (strcasecmp(kw, "table") == 0) {
        long t = strtol(val, NULL, 10);
        if (t > 0 && t < 256) table = (int)t;
        p += consumed; while (*p == ' ') p++;
        continue;
      }
    }
    /* Single keyword without value */
    if (sscanf(p, "%31s%n", kw, &consumed) == 1) {
      if (strcasecmp(kw, "kernel") == 0) {
        do_kernel = true;
        p += consumed; while (*p == ' ') p++;
        continue;
      }
    }
    break;
  }

  if (nh.s_addr == 0 && ifname[0] == 0) {
    cli_printf(fd, "%% Need 'via <nexthop>' or 'dev <ifname>'\n");
    return;
  }

  /* ── Inject into BGP RIB ─────────────────────────────────────────────── */
  bgp_attrs_t a;
  attrs_init(&a);
  a.origin = 0; /* IGP */
  if (nh.s_addr != 0) {
    a.has_next_hop = true;
    a.next_hop     = nh;
  }
  a.has_local_pref = true;
  a.local_pref     = 1;   /* lower than BGP best-paths */

  rib4_add_or_replace(&c->rib, NULL, pfx, plen, &a);
  int ei = rib4_find_entry(&c->rib, pfx, plen);
  if (ei >= 0) rib4_recompute_best(&c->rib, ei);

  /* ── Program kernel FIB ──────────────────────────────────────────────── */
  int kern_ok = 0;
  if (ifname[0]) {
    kern_ok = (nl_route_replace_v4_dev(pfx, plen, nh, ifname, table) == 0);
    if (!kern_ok)
      cli_printf(fd, "%% Kernel FIB: %s\n", strerror(errno));
  } else if (do_kernel && nh.s_addr != 0) {
    kern_ok = (nl_route_replace_v4(pfx, plen, nh, table) == 0);
    if (!kern_ok)
      cli_printf(fd, "%% Kernel FIB: %s\n", strerror(errno));
  }

  /* ── Report ──────────────────────────────────────────────────────────── */
  char nh_buf[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &nh, nh_buf, sizeof(nh_buf));

  cli_printf(fd, "Route %s/%u", inet_ntoa(pfx), plen);
  if (nh.s_addr)  cli_printf(fd, " via %s", nh_buf);
  if (ifname[0])  cli_printf(fd, " dev %s", ifname);
  cli_printf(fd, " added to RIB");
  if (kern_ok)    cli_printf(fd, " and kernel FIB (table %d)", table);
  cli_printf(fd, ".\n");
}

/*
 * no route <prefix>/<len> [table <id>] [kernel]
 *
 * Removes a static (from==NULL) route from the BGP RIB.  With "kernel"
 * also removes it from the kernel FIB.
 */
static void cmd_no_route(int fd, bgp_core_t* c, const char* args)
{
  char pfx_str[32];
  if (sscanf(args, "%31s", pfx_str) != 1) {
    cli_printf(fd, "%% Usage: no route <prefix>/<len> [table <id>] [kernel]\n");
    return;
  }

  struct in_addr pfx;
  uint8_t plen;
  if (parse_prefix(pfx_str, &pfx, &plen) < 0) {
    cli_printf(fd, "%% Invalid prefix: %s\n", pfx_str);
    return;
  }

  int  table     = 254;
  bool do_kernel = false;

  /* Scan optional "table <id>" and "kernel" */
  const char* tp = strstr(args, "table ");
  if (tp) {
    long t = strtol(tp + 6, NULL, 10);
    if (t > 0 && t < 256) table = (int)t;
  }
  if (strstr(args, "kernel")) do_kernel = true;

  int ei = rib4_find_entry(&c->rib, pfx, plen);
  if (ei < 0) {
    cli_printf(fd, "%% Route %s not found in RIB.\n", pfx_str);
    return;
  }

  rib4_withdraw(&c->rib, NULL, pfx, plen);
  ei = rib4_find_entry(&c->rib, pfx, plen);
  if (ei >= 0) rib4_recompute_best(&c->rib, ei);

  if (do_kernel) {
    if (nl_route_delete_v4(pfx, plen, table) < 0)
      cli_printf(fd, "%% Kernel FIB remove failed: %s\n", strerror(errno));
    else
      cli_printf(fd, "Route %s removed from RIB and kernel FIB (table %d).\n",
                 pfx_str, table);
  } else {
    cli_printf(fd, "Route %s removed from RIB.\n", pfx_str);
  }
}

/*
 * ipv6 route <prefix>/<len> [via <nh>] [dev <if>] [table <id>] [kernel]
 *
 * Injects a static IPv6 route. Similar to 'ip route' but for IPv6 prefixes.
 */
static void cmd_ipv6_route(int fd, bgp_core_t* c, const char* args)
{
  /* First token must be the prefix */
  char pfx_str[64];
  if (sscanf(args, "%63s", pfx_str) != 1) {
    cli_printf(fd, "%% Usage: ipv6 route <prefix>/<len> [via <nh>] [dev <if>] "
                   "[table <id>] [kernel]\n");
    return;
  }

  struct in6_addr pfx;
  uint8_t plen;
  if (parse_prefix_v6(pfx_str, &pfx, &plen) < 0) {
    cli_printf(fd, "%% Invalid IPv6 prefix: %s\n", pfx_str);
    return;
  }

  /* Scan remaining tokens */
  struct in6_addr nh = {0};
  char   ifname[16]  = {0};
  int    table       = 254; /* RT_TABLE_MAIN */
  bool   do_kernel   = false;

  const char* p = args + strlen(pfx_str);
  while (*p == ' ') p++;

  /* Parse keyword arguments */
  while (*p) {
    char kw[32], val[64];
    int consumed = 0;
    if (sscanf(p, "%31s %63s%n", kw, val, &consumed) == 2) {
      if (strcasecmp(kw, "via") == 0) {
        if (inet_pton(AF_INET6, val, &nh) != 1) {
          cli_printf(fd, "%% Invalid IPv6 nexthop: %s\n", val);
          return;
        }
        p += consumed; while (*p == ' ') p++;
        continue;
      }
      if (strcasecmp(kw, "dev") == 0) {
        strncpy(ifname, val, sizeof(ifname) - 1);
        ifname[sizeof(ifname) - 1] = 0;
        p += consumed; while (*p == ' ') p++;
        continue;
      }
      if (strcasecmp(kw, "table") == 0) {
        long t = strtol(val, NULL, 10);
        if (t > 0 && t < 256) table = (int)t;
        p += consumed; while (*p == ' ') p++;
        continue;
      }
      p += consumed; while (*p == ' ') p++;
    } else {
      if (strcasecmp(p, "kernel") == 0) {
        do_kernel = true;
        p += 6;
        while (*p == ' ') p++;
      } else {
        break;
      }
    }
  }

  /* ── Update RIB ────────────────────────────────────────────────────────── */
  bgp_attrs_t a = {0};
  a.origin = 0; /* IGP */
  rib6_add_or_replace(&c->rib6, NULL, pfx, plen, &a, nh);
  rib6_recompute_best(&c->rib6, rib6_find_entry(&c->rib6, pfx, plen));

  /* ── Update kernel FIB ───────────────────────────────────────────────── */
  bool kern_ok = false;
  if (ifname[0]) {
    kern_ok = (nl_route_replace_v6_dev(pfx, plen, nh, ifname, table) == 0);
    if (!kern_ok)
      cli_printf(fd, "%% Kernel FIB: %s\n", strerror(errno));
  } else if (do_kernel && memcmp(&nh, &(struct in6_addr){0}, sizeof(struct in6_addr)) != 0) {
    kern_ok = (nl_route_replace_v6(pfx, plen, nh, table) == 0);
    if (!kern_ok)
      cli_printf(fd, "%% Kernel FIB: %s\n", strerror(errno));
  }

  /* ── Report ──────────────────────────────────────────────────────────── */
  char nh_buf[INET6_ADDRSTRLEN];
  inet_ntop(AF_INET6, &nh, nh_buf, sizeof(nh_buf));

  cli_printf(fd, "IPv6 route %s/%u", pfx_str, plen);
  if (memcmp(&nh, &(struct in6_addr){0}, sizeof(struct in6_addr)) != 0)
    cli_printf(fd, " via %s", nh_buf);
  if (ifname[0])
    cli_printf(fd, " dev %s", ifname);
  cli_printf(fd, " added to RIB");
  if (kern_ok)
    cli_printf(fd, " and kernel FIB (table %d)", table);
  cli_printf(fd, ".\n");
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

/* ──────────────────────────────────────────────────────────────────────────── */
/* Interface Management Commands */
/* ──────────────────────────────────────────────────────────────────────────── */

static int interface_dump_cb(const sys_interface_t* iface, void* arg)
{
  int fd = (intptr_t)arg;
  const char* status = (iface->flags & IF_UP) ? "UP" : "DOWN";
  const char* running = (iface->flags & IF_RUNNING) ? "RUNNING" : "";

  cli_printf(fd, "%-16s %s %s", iface->name, status, running);

  if (iface->mtu > 0)
    cli_printf(fd, " MTU %u", iface->mtu);

  if (iface->addr_v4.s_addr != 0)
    cli_printf(fd, " %s/%u", inet_ntoa(iface->addr_v4), iface->plen_v4);

  if (memcmp(&iface->addr_v6, &in6addr_any, 16) != 0) {
    char addr_str[64];
    inet_ntop(AF_INET6, &iface->addr_v6, addr_str, sizeof(addr_str));
    cli_printf(fd, " %s/%u", addr_str, iface->plen_v6);
  }

  cli_send(fd, "\n", 1);
  return 0;
}

/* ──────────────────────────────────────────────────────────────────────────── */
/* Interface Validation Helpers */

/**
 * Helper structure for interface name validation.
 * Used to search for an interface name in nl_interface_dump() results.
 */
struct iface_find_ctx {
  const char* target_name;
  int found;
};

/**
 * Callback to check if a given interface name exists in the system.
 */
static int interface_find_cb(const sys_interface_t* iface, void* arg)
{
  struct iface_find_ctx* ctx = (struct iface_find_ctx*)arg;
  if (strcmp(iface->name, ctx->target_name) == 0) {
    ctx->found = 1;
    return 1;  /* Stop iteration */
  }
  return 0;   /* Continue iteration */
}

/**
 * Validate that an interface name exists in the system.
 * Returns 1 if found, 0 if not found.
 */
static int interface_name_exists(const char* name)
{
  struct iface_find_ctx ctx = { .target_name = name, .found = 0 };
  nl_interface_dump(interface_find_cb, &ctx);
  return ctx.found;
}

/* ──────────────────────────────────────────────────────────────────────────── */
/* Interface Configuration Commands */

static void cmd_interface(int fd, bgp_core_t* c, cli_client_t* cl, const char* name)
{
  if (!name || *name == '\0') {
    cli_printf(fd, "%% Interface name required\r\n");
    return;
  }

  /* Validate interface name exists in system */
  if (!interface_name_exists(name)) {
    cli_printf(fd, "%% Interface '%s' not found in system\r\n", name);
    return;
  }

  /* Find or create interface in core->interfaces array */
  interface_cfg_t* iface = NULL;
  for (int i = 0; i < c->interface_count && i < 64; i++) {
    if (strcmp(c->interfaces[i].name, name) == 0) {
      iface = &c->interfaces[i];
      break;
    }
  }

  if (!iface && c->interface_count < 64) {
    iface = &c->interfaces[c->interface_count++];
    strncpy(iface->name, name, sizeof(iface->name) - 1);
    iface->name[sizeof(iface->name) - 1] = '\0';
  }

  if (!iface) {
    cli_printf(fd, "%% Cannot create interface: table full\r\n");
    return;
  }

  /* Enter interface mode */
  cl->mode = MODE_INTERFACE;
  strncpy(cl->context_name, name, sizeof(cl->context_name) - 1);
  cl->context_name[sizeof(cl->context_name) - 1] = '\0';
  cl->context_obj = (void*)iface;
  cli_printf(fd, "Entering interface configuration mode for %s\r\n", name);
}

static void cmd_interface_loopback(int fd, bgp_core_t* c, cli_client_t* cl, const char* number)
{
  if (!number || *number == '\0') {
    cli_printf(fd, "%% Loopback number required\r\n");
    return;
  }

  char ifname[16];
  snprintf(ifname, sizeof(ifname), "lo%s", number);

  /* Try to create loopback interface in kernel */
  int rc = nl_interface_create_loopback(ifname);
  if (rc < 0) {
    cli_printf(fd, "%% Failed to create loopback %s\r\n", ifname);
    return;
  }

  /* Find or create in interface array */
  interface_cfg_t* iface = NULL;
  for (int i = 0; i < c->interface_count && i < 64; i++) {
    if (strcmp(c->interfaces[i].name, ifname) == 0) {
      iface = &c->interfaces[i];
      break;
    }
  }

  if (!iface && c->interface_count < 64) {
    iface = &c->interfaces[c->interface_count++];
    strncpy(iface->name, ifname, sizeof(iface->name) - 1);
    iface->name[sizeof(iface->name) - 1] = '\0';
  }

  if (!iface) {
    cli_printf(fd, "%% Cannot configure loopback: table full\r\n");
    return;
  }

  /* Enter interface mode */
  cl->mode = MODE_INTERFACE;
  strncpy(cl->context_name, ifname, sizeof(cl->context_name) - 1);
  cl->context_name[sizeof(cl->context_name) - 1] = '\0';
  cl->context_obj = (void*)iface;
  cli_printf(fd, "Entering interface configuration mode for %s\r\n", ifname);
}

static void cmd_interface_ip_address(int fd, bgp_core_t* c, cli_client_t* cl, const char* addr_str)
{
  (void)c;

  interface_cfg_t* iface = (interface_cfg_t*)cl->context_obj;
  if (!iface) {
    cli_printf(fd, "%% Not in interface configuration mode\r\n");
    return;
  }

  if (!addr_str || *addr_str == '\0') {
    cli_printf(fd, "%% Address required (format: <addr>/<prefix>)\r\n");
    return;
  }

  /* Parse address/prefix length */
  char addr_copy[64];
  strncpy(addr_copy, addr_str, sizeof(addr_copy) - 1);
  addr_copy[sizeof(addr_copy) - 1] = '\0';

  char* slash = strchr(addr_copy, '/');
  if (!slash) {
    cli_printf(fd, "%% Invalid format: must be <addr>/<prefix>\r\n");
    return;
  }

  *slash = '\0';
  const char* plen_str = slash + 1;
  int plen = atoi(plen_str);

  if (plen < 1 || plen > 32) {
    cli_printf(fd, "%% Prefix length must be 1-32\r\n");
    return;
  }

  struct in_addr addr;
  if (inet_aton(addr_copy, &addr) == 0) {
    cli_printf(fd, "%% Invalid IPv4 address\r\n");
    return;
  }

  /* Set address in kernel and store in interface config */
  int rc = nl_interface_set_addr_v4(iface->name, addr, (uint8_t)plen);
  if (rc < 0) {
    cli_printf(fd, "%% Failed to set address on %s\r\n", iface->name);
    return;
  }

  iface->addr_v4 = addr;
  iface->plen_v4 = (uint8_t)plen;
  cli_printf(fd, "IPv4 address %s/%d set on %s\r\n", addr_copy, plen, iface->name);
}

static void cmd_interface_ipv6_address(int fd, bgp_core_t* c, cli_client_t* cl, const char* addr_str)
{
  (void)c;

  interface_cfg_t* iface = (interface_cfg_t*)cl->context_obj;
  if (!iface) {
    cli_printf(fd, "%% Not in interface configuration mode\r\n");
    return;
  }

  if (!addr_str || *addr_str == '\0') {
    cli_printf(fd, "%% Address required (format: <addr>/<prefix>)\r\n");
    return;
  }

  /* Parse address/prefix length */
  char addr_copy[128];
  strncpy(addr_copy, addr_str, sizeof(addr_copy) - 1);
  addr_copy[sizeof(addr_copy) - 1] = '\0';

  char* slash = strchr(addr_copy, '/');
  if (!slash) {
    cli_printf(fd, "%% Invalid format: must be <addr>/<prefix>\r\n");
    return;
  }

  *slash = '\0';
  const char* plen_str = slash + 1;
  int plen = atoi(plen_str);

  if (plen < 1 || plen > 128) {
    cli_printf(fd, "%% Prefix length must be 1-128\r\n");
    return;
  }

  struct in6_addr addr;
  if (inet_pton(AF_INET6, addr_copy, &addr) != 1) {
    cli_printf(fd, "%% Invalid IPv6 address\r\n");
    return;
  }

  /* Set address in kernel and store in interface config */
  int rc = nl_interface_set_addr_v6(iface->name, addr, (uint8_t)plen);
  if (rc < 0) {
    cli_printf(fd, "%% Failed to set IPv6 address on %s\r\n", iface->name);
    return;
  }

  iface->addr_v6 = addr;
  iface->plen_v6 = (uint8_t)plen;
  cli_printf(fd, "IPv6 address %s/%d set on %s\r\n", addr_copy, plen, iface->name);
}

static void cmd_interface_description(int fd, bgp_core_t* c, cli_client_t* cl, const char* desc)
{
  (void)c;

  interface_cfg_t* iface = (interface_cfg_t*)cl->context_obj;
  if (!iface) {
    cli_printf(fd, "%% Not in interface configuration mode\r\n");
    return;
  }

  if (!desc || *desc == '\0') {
    cli_printf(fd, "%% Description required\r\n");
    return;
  }

  strncpy(iface->description, desc, sizeof(iface->description) - 1);
  iface->description[sizeof(iface->description) - 1] = '\0';
  cli_printf(fd, "Description set to: %s\r\n", iface->description);
}

static void cmd_interface_mtu(int fd, bgp_core_t* c, cli_client_t* cl, const char* mtu_str)
{
  (void)c;

  interface_cfg_t* iface = (interface_cfg_t*)cl->context_obj;
  if (!iface) {
    cli_printf(fd, "%% Not in interface configuration mode\r\n");
    return;
  }

  if (!mtu_str || *mtu_str == '\0') {
    cli_printf(fd, "%% MTU value required\r\n");
    return;
  }

  int mtu = atoi(mtu_str);
  if (mtu < 68 || mtu > 65535) {
    cli_printf(fd, "%% MTU must be 68-65535\r\n");
    return;
  }

  int rc = nl_interface_set_mtu(iface->name, (uint32_t)mtu);
  if (rc < 0) {
    cli_printf(fd, "%% Failed to set MTU on %s\r\n", iface->name);
    return;
  }

  iface->mtu = mtu;
  cli_printf(fd, "MTU set to %d on %s\r\n", mtu, iface->name);
}

static void cmd_interface_shutdown(int fd, bgp_core_t* c, cli_client_t* cl, int shutdown_flag)
{
  (void)c;

  interface_cfg_t* iface = (interface_cfg_t*)cl->context_obj;
  if (!iface) {
    cli_printf(fd, "%% Not in interface configuration mode\r\n");
    return;
  }

  int rc = nl_interface_set_up(iface->name, shutdown_flag ? 0 : 1);
  if (rc < 0) {
    cli_printf(fd, "%% Failed to change interface state on %s\r\n", iface->name);
    return;
  }

  iface->shutdown = shutdown_flag;
  cli_printf(fd, "Interface %s is now %s\r\n", iface->name, shutdown_flag ? "down" : "up");
}

/**
 * Callback context for filtering interfaces by name.
 */
struct show_iface_ctx {
  int fd;
  const char* filter_name;  /* NULL or empty = show all */
  int found;                /* Track if any matching interface found */
  int printed_header;       /* Track if header already printed */
};

/**
 * Callback for showing specific interface(s).
 * If filter_name is set, only shows matching interface.
 * Otherwise shows all interfaces.
 */
static int show_interface_cb(const sys_interface_t* iface, void* arg)
{
  struct show_iface_ctx* ctx = (struct show_iface_ctx*)arg;

  /* If filter set, skip non-matching interfaces */
  if (ctx->filter_name && *ctx->filter_name != '\0') {
    if (strcmp(iface->name, ctx->filter_name) != 0)
      return 0;  /* Skip this interface */
    ctx->found = 1;
  }

  /* Print header on first match */
  if (!ctx->printed_header) {
    cli_printf(ctx->fd, "\n%-16s State         MTU Address\n", "Interface");
    cli_printf(ctx->fd, "%-16s %-13s --- -------\n", "=========", "=====");
    ctx->printed_header = 1;
  }

  /* Use existing interface_dump_cb logic */
  interface_dump_cb(iface, (void*)(intptr_t)ctx->fd);

  return 0;  /* Continue iteration */
}

static void cmd_show_interface(int fd, bgp_core_t* c, const char* name)
{
  (void)c;

  struct show_iface_ctx ctx = {
    .fd = fd,
    .filter_name = name,
    .found = 0,
    .printed_header = 0
  };

  nl_interface_dump(show_interface_cb, &ctx);

  /* If filtering and no match found, show error */
  if (name && *name != '\0' && !ctx.found) {
    cli_printf(fd, "%% Interface '%s' not found\n", name);
  }

  cli_send(fd, "\n", 1);
}

/* ──────────────────────────────────────────────────────────────────────────── */
/* Configuration Save Commands */
/* ──────────────────────────────────────────────────────────────────────────── */

static void cmd_write_config(int fd, bgp_core_t* c, const char* path)
{
  const char* target_path = "/etc/bgpd.conf";

  if (path && *path != '\0') {
    /* Strip leading whitespace */
    while (*path == ' ' || *path == '\t') path++;
    if (*path != '\0')
      target_path = path;
  }

  if (bgp_save_config(target_path, c) == 0) {
    cli_printf(fd, "Configuration saved to %s\n", target_path);
  } else {
    cli_printf(fd, "%% Failed to save configuration to %s\n", target_path);
  }
}

/**
 * Convert interface name to Cisco-like format for display.
 * Converts kernel names (lo0, lo1) to Cisco format (loopback 0, loopback 1).
 */
static void interface_name_to_cisco_display(const char* name, char* buf, size_t buflen)
{
  if (!name || !buf || buflen == 0) return;

  if (strlen(name) >= 3 && name[0] == 'l' && name[1] == 'o' && isdigit(name[2])) {
    snprintf(buf, buflen, "loopback %s", &name[2]);
    return;
  }

  strncpy(buf, name, buflen - 1);
  buf[buflen - 1] = '\0';
}

static void cmd_show_config(int fd, bgp_core_t* c, const char* args)
{
  (void)args;

  time_t now = time(NULL);
  cli_printf(fd, "! BGP Configuration\n");
  cli_printf(fd, "! Generated: %s", ctime(&now));
  cli_printf(fd, "!\n");

  /* Write VRF definitions */
  if (c->vrfs && c->vrfs->vrf_count > 0) {
    cli_printf(fd, "! VRF Definitions\n");
    for (int i = 0; i < c->vrfs->vrf_count; i++) {
      vrf_t* vrf = &c->vrfs->vrfs[i];
      if (vrf->name[0] == '\0') continue;

      cli_printf(fd, "vrf definition %s\n", vrf->name);

      if (vrf->rd.asn != 0 || vrf->rd.val != 0)
        cli_printf(fd, "  rd %u:%u\n", vrf->rd.asn, vrf->rd.val);

      for (int j = 0; j < vrf->import_count; j++)
        cli_printf(fd, "  route-target import %u:%u\n", vrf->import_rts[j].asn, vrf->import_rts[j].val);

      for (int j = 0; j < vrf->export_count; j++)
        cli_printf(fd, "  route-target export %u:%u\n", vrf->export_rts[j].asn, vrf->export_rts[j].val);

      if (vrf->table_id > 0)
        cli_printf(fd, "  table %u\n", vrf->table_id);

      if (vrf->vni > 0)
        cli_printf(fd, "  vni %u\n", vrf->vni);

      if (vrf->bridge[0] != '\0')
        cli_printf(fd, "  bridge %s\n", vrf->bridge);

      cli_printf(fd, "!\n");
    }
  }

  /* Write network interfaces */
  if (c->interface_count > 0) {
    cli_printf(fd, "! Network Interfaces\n");
    for (int i = 0; i < c->interface_count && i < 64; i++) {
      interface_cfg_t* iface = &c->interfaces[i];
      if (iface->name[0] == '\0') continue;

      char cisco_name[64];
      interface_name_to_cisco_display(iface->name, cisco_name, sizeof(cisco_name));
      cli_printf(fd, "interface %s\n", cisco_name);

      if (iface->description[0] != '\0')
        cli_printf(fd, "  description \"%s\"\n", iface->description);

      if (iface->addr_v4.s_addr != 0)
        cli_printf(fd, "  ip address %s/%u\n",
                inet_ntoa(iface->addr_v4), iface->plen_v4);

      if (memcmp(&iface->addr_v6, &in6addr_any, 16) != 0) {
        char addr_str[64];
        inet_ntop(AF_INET6, &iface->addr_v6, addr_str, sizeof(addr_str));
        cli_printf(fd, "  ipv6 address %s/%u\n", addr_str, iface->plen_v6);
      }

      if (iface->mtu != 0 && iface->mtu != 1500)
        cli_printf(fd, "  mtu %u\n", iface->mtu);

      if (!iface->shutdown)
        cli_printf(fd, "  no shutdown\n");
      else
        cli_printf(fd, "  shutdown\n");

      cli_printf(fd, "!\n");
    }
  }

  /* Write prefix-lists */
  if (c->pol.plist_count > 0) {
    cli_printf(fd, "! Prefix-lists\n");
    for (int i = 0; i < c->pol.plist_count; i++) {
      prefix_list_t* pl = &c->pol.plists[i];
      if (pl->name[0] == '\0') continue;

      for (int j = 0; j < pl->rule_count; j++) {
        prefix_list_rule_t* rule = &pl->rules[j];
        cli_printf(fd, "ip prefix-list %s seq %d %s %s/%u",
                  pl->name, rule->seq, rule->permit ? "permit" : "deny",
                  inet_ntoa(rule->pfx), rule->plen);
        if (rule->ge > 0 || rule->le > 0) {
          cli_printf(fd, " ");
          if (rule->ge > 0) cli_printf(fd, "ge %u ", rule->ge);
          if (rule->le > 0) cli_printf(fd, "le %u", rule->le);
        }
        cli_printf(fd, "\n");
      }
    }
    cli_printf(fd, "!\n");
  }

  /* Write route-maps */
  if (c->pol.rmap_count > 0) {
    cli_printf(fd, "! Route-maps\n");
    for (int i = 0; i < c->pol.rmap_count; i++) {
      route_map_t* rm = &c->pol.rmaps[i];
      if (rm->name[0] == '\0') continue;

      for (int j = 0; j < rm->ent_count; j++) {
        route_map_entry_t* ent = &rm->ents[j];
        cli_printf(fd, "route-map %s %s %d\n",
                  rm->name, ent->permit ? "permit" : "deny", ent->seq);

        if (ent->match_plist[0] != '\0')
          cli_printf(fd, "  match ip address prefix-list %s\n", ent->match_plist);

        if (ent->set_local_pref)
          cli_printf(fd, "  set local-preference %u\n", ent->local_pref);

        if (ent->set_med)
          cli_printf(fd, "  set metric %u\n", ent->med);

        if (ent->set_next_hop_self)
          cli_printf(fd, "  set ip next-hop self\n");

        if (ent->set_community) {
          cli_printf(fd, "  set community");
          for (int k = 0; k < ent->community_count; k++) {
            uint32_t asn = (ent->community[k] >> 16) & 0xFFFF;
            uint32_t val = ent->community[k] & 0xFFFF;
            cli_printf(fd, " %u:%u", asn, val);
          }
          if (ent->community_additive)
            cli_printf(fd, " additive");
          cli_printf(fd, "\n");
        }

        if (ent->set_as_path_prepend) {
          cli_printf(fd, "  set as-path prepend");
          for (int k = 0; k < ent->prepend_count; k++)
            cli_printf(fd, " %u", ent->prepend_asn);
          cli_printf(fd, "\n");
        }
      }
    }
    cli_printf(fd, "!\n");
  }

  /* Write BGP router global config */
  if (c->local_asn != 0) {
    cli_printf(fd, "router bgp %u\n", c->local_asn);

    if (c->router_id.s_addr != 0)
      cli_printf(fd, "  bgp router-id %s\n", inet_ntoa(c->router_id));

    if (c->cluster_id.s_addr != 0)
      cli_printf(fd, "  bgp cluster-id %s\n", inet_ntoa(c->cluster_id));

    /* Write neighbors */
    for (int i = 0; i < c->peer_count && i < 64; i++) {
      bgp_peer_t* p = c->peers[i];
      if (!p) continue;

      cli_printf(fd, "  neighbor %s remote-as %u\n",
              inet_ntoa(p->addr), p->remote_asn_cfg);

      if (p->description[0] != '\0')
        cli_printf(fd, "  neighbor %s description \"%s\"\n",
                inet_ntoa(p->addr), p->description);

      if (p->is_rr_client)
        cli_printf(fd, "  neighbor %s route-reflector-client\n",
                inet_ntoa(p->addr));

      if (p->rmap_in[0] != '\0')
        cli_printf(fd, "  neighbor %s route-map %s in\n",
                inet_ntoa(p->addr), p->rmap_in);

      if (p->rmap_out[0] != '\0')
        cli_printf(fd, "  neighbor %s route-map %s out\n",
                inet_ntoa(p->addr), p->rmap_out);
    }

    /* Write address-families with networks */
    bool has_vpnv4 = false;
    char vpnv4_vrfs[32][64];
    int vpnv4_vrf_count = 0;

    for (int i = 0; i < c->network_count; i++) {
      if (c->networks[i].af == 3) {
        has_vpnv4 = true;
        /* Collect unique VRF names */
        bool found = false;
        for (int j = 0; j < vpnv4_vrf_count; j++) {
          if (strcmp(vpnv4_vrfs[j], c->networks[i].vrf_name) == 0) {
            found = true;
            break;
          }
        }
        if (!found && vpnv4_vrf_count < 32) {
          strncpy(vpnv4_vrfs[vpnv4_vrf_count], c->networks[i].vrf_name, 63);
          vpnv4_vrf_count++;
        }
      }
    }

    /* IPv4 Unicast */
    cli_printf(fd, "  address-family ipv4 unicast\n");
    for (int i = 0; i < c->network_count; i++) {
      if (c->networks[i].af != 1) continue;
      char buf[INET_ADDRSTRLEN];
      inet_ntop(AF_INET, &c->networks[i].prefix.addr4, buf, sizeof(buf));
      cli_printf(fd, "    network %s/%u\n", buf, c->networks[i].plen);
    }
    for (int i = 0; i < c->peer_count && i < 64; i++) {
      bgp_peer_t* p = c->peers[i];
      if (p) cli_printf(fd, "    neighbor %s activate\n", inet_ntoa(p->addr));
    }
    cli_printf(fd, "  exit-address-family\n");

    /* IPv6 Unicast */
    cli_printf(fd, "  address-family ipv6 unicast\n");
    for (int i = 0; i < c->network_count; i++) {
      if (c->networks[i].af != 2) continue;
      char buf[INET6_ADDRSTRLEN];
      inet_ntop(AF_INET6, &c->networks[i].prefix.addr6, buf, sizeof(buf));
      cli_printf(fd, "    network %s/%u\n", buf, c->networks[i].plen);
    }
    for (int i = 0; i < c->peer_count && i < 64; i++) {
      bgp_peer_t* p = c->peers[i];
      if (p) cli_printf(fd, "    neighbor %s activate\n", inet_ntoa(p->addr));
    }
    cli_printf(fd, "  exit-address-family\n");

    /* VPNv4 by VRF */
    if (has_vpnv4) {
      for (int v = 0; v < vpnv4_vrf_count; v++) {
        cli_printf(fd, "  address-family ipv4 vrf %s\n", vpnv4_vrfs[v]);
        for (int i = 0; i < c->network_count; i++) {
          if (c->networks[i].af != 3) continue;
          if (strcmp(c->networks[i].vrf_name, vpnv4_vrfs[v]) != 0) continue;
          char buf[INET_ADDRSTRLEN];
          inet_ntop(AF_INET, &c->networks[i].prefix.addr4, buf, sizeof(buf));
          cli_printf(fd, "    network %s/%u\n", buf, c->networks[i].plen);
        }
        for (int i = 0; i < c->peer_count && i < 64; i++) {
          bgp_peer_t* p = c->peers[i];
          if (p) cli_printf(fd, "    neighbor %s activate\n", inet_ntoa(p->addr));
        }
        cli_printf(fd, "  exit-address-family\n");
      }
    }

    /* EVPN */
    cli_printf(fd, "  address-family l2vpn evpn\n");
    for (int i = 0; i < c->peer_count && i < 64; i++) {
      bgp_peer_t* p = c->peers[i];
      if (p) cli_printf(fd, "    neighbor %s activate\n", inet_ntoa(p->addr));
    }
    cli_printf(fd, "  exit-address-family\n");

    /* VPLS */
    cli_printf(fd, "  address-family l2vpn vpls\n");
    for (int i = 0; i < c->peer_count && i < 64; i++) {
      bgp_peer_t* p = c->peers[i];
      if (p) cli_printf(fd, "    neighbor %s activate\n", inet_ntoa(p->addr));
    }
    cli_printf(fd, "  exit-address-family\n");

    cli_printf(fd, "!\n");
  }
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

/** show ipv6 bgp — IPv6 unicast RIB dump */
static void cmd_show_ipv6_bgp(int fd, bgp_core_t* c)
{
  cli_printf(fd, "\nStatus codes: * valid, > best\n");
  cli_printf(fd, "Origin codes:  i - IGP, e - EGP, ? - incomplete\n\n");
  cli_printf(fd, "   Network                       Next Hop         Metric LocPrf Weight Path\n");

  for (int i = 0; i < c->rib6.entry_count; i++) {
    const rib_entry6_t* e = &c->rib6.entries[i];
    if (e->path_count == 0) continue;

    char pfxbuf[INET6_ADDRSTRLEN + 4];
    inet_ntop(AF_INET6, &e->pfx.pfx, pfxbuf, sizeof(pfxbuf) - 4);
    int len = strlen(pfxbuf);
    snprintf(pfxbuf + len, 4, "/%u", e->pfx.plen);

    for (int j = 0; j < e->path_count; j++) {
      const rib_path6_t* path = &e->paths[j];
      char valid = (e->best_index >= 0) ? '*' : ' ';
      char best  = (j == e->best_index) ? '>' : ' ';
      char origin_ch = (path->attrs.origin == 0) ? 'i'
                     : (path->attrs.origin == 1) ? 'e' : '?';

      char nh_buf[INET6_ADDRSTRLEN];
      if (path->attrs.has_next_hop)
        inet_ntop(AF_INET6, &path->attrs.next_hop, nh_buf, sizeof(nh_buf));
      else
        snprintf(nh_buf, sizeof(nh_buf), "::");

      uint32_t med   = path->attrs.has_med       ? path->attrs.med       : 0;
      uint32_t locpf = path->attrs.has_local_pref ? path->attrs.local_pref : 100;

      cli_printf(fd, "%c%c %-35s %-16s %6u %6u      0 ",
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
static int cli_dispatch(cli_client_t* cl, bgp_core_t* c, const char* line)
{
  int fd = cl->fd;

  /* Skip leading whitespace */
  while (*line == ' ' || *line == '\t') line++;

  /* Handle mode-based command routing */
  if (cl->mode == MODE_INTERFACE) {
    /* Interface configuration subcommands */
    if (strncasecmp(line, "ip address ", 11) == 0) {
      const char* arg = line + 11;
      while (*arg == ' ' || *arg == '\t') arg++;
      cmd_interface_ip_address(fd, c, cl, arg);
    } else if (strncasecmp(line, "ipv6 address ", 13) == 0) {
      const char* arg = line + 13;
      while (*arg == ' ' || *arg == '\t') arg++;
      cmd_interface_ipv6_address(fd, c, cl, arg);
    } else if (strncasecmp(line, "description ", 12) == 0) {
      const char* arg = line + 12;
      while (*arg == ' ' || *arg == '\t') arg++;
      cmd_interface_description(fd, c, cl, arg);
    } else if (strncasecmp(line, "mtu ", 4) == 0) {
      const char* arg = line + 4;
      while (*arg == ' ' || *arg == '\t') arg++;
      cmd_interface_mtu(fd, c, cl, arg);
    } else if (strncasecmp(line, "shutdown", 8) == 0) {
      cmd_interface_shutdown(fd, c, cl, 1);
    } else if (strncasecmp(line, "no shutdown", 11) == 0) {
      cmd_interface_shutdown(fd, c, cl, 0);
    } else if (strncasecmp(line, "exit", 4) == 0) {
      cl->mode = MODE_EXEC;
      cl->context_name[0] = '\0';
      cl->context_obj = NULL;
    } else if (*line == '\0' || *line == '\r' || *line == '\n') {
      /* empty line — just re-prompt */
    } else {
      cli_printf(fd, "%% Unknown command in interface mode: %s\r\n", line);
    }
  } else {
    /* Normal EXEC mode commands */
    if (strncasecmp(line, "show interface ", 14) == 0) {
      /* Skip "show interface " and any additional whitespace */
      const char* name = line + 14;
      while (*name == ' ' || *name == '\t') name++;
      cmd_show_interface(fd, c, name);
    } else if (strncasecmp(line, "show interface", 14) == 0) {
      cmd_show_interface(fd, c, NULL);
    } else if (strncasecmp(line, "interface loopback ", 19) == 0) {
      /* Skip "interface loopback " and any additional whitespace */
      const char* name = line + 19;
      while (*name == ' ' || *name == '\t') name++;
      cmd_interface_loopback(fd, c, cl, name);
    } else if (strncasecmp(line, "interface ", 10) == 0) {
      /* Skip "interface " and any additional whitespace */
      const char* name = line + 10;
      while (*name == ' ' || *name == '\t') name++;
      cmd_interface(fd, c, cl, name);
    } else if (strncasecmp(line, "write config", 12) == 0) {
      cmd_write_config(fd, c, line + 12);
    } else if (strncasecmp(line, "show config", 11) == 0) {
      cmd_show_config(fd, c, line + 11);
    } else if (strncasecmp(line, "show bgp summary", 16) == 0) {
      cmd_show_bgp_summary(fd, c);
    } else if (strncasecmp(line, "show ip bgp", 11) == 0) {
      cmd_show_ip_bgp(fd, c);
    } else if (strncasecmp(line, "show ipv6 bgp", 13) == 0) {
      cmd_show_ipv6_bgp(fd, c);
    } else if (strncasecmp(line, "show bgp neighbors", 18) == 0) {
      cmd_show_bgp_neighbors(fd, c);
    } else if (strncasecmp(line, "show route kernel", 17) == 0) {
      cmd_show_route_kernel(fd);
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
    } else if (strncasecmp(line, "ip route ", 9) == 0) {
      cmd_ip_route(fd, c, line + 9);
    } else if (strncasecmp(line, "ipv6 route ", 11) == 0) {
      cmd_ipv6_route(fd, c, line + 11);
    } else if (strncasecmp(line, "no route ", 9) == 0) {
      cmd_no_route(fd, c, line + 9);
    } else if (strncasecmp(line, "clear bgp all", 13) == 0) {
      cmd_clear_bgp_all(fd, c);
    } else if (strncasecmp(line, "clear bgp ", 10) == 0) {
      cmd_clear_bgp_peer(fd, c, line + 10);
    } else if (strncasecmp(line, "exit", 4) == 0 ||
               strncasecmp(line, "quit", 4) == 0) {
      cli_send(fd, "Bye.\r\n", 6);
      return -1; /* signal close */
    } else if (*line == '\0' || *line == '\r' || *line == '\n') {
      /* empty line — just re-prompt */
    } else {
      cli_printf(fd, "%% Unknown command: %s\r\n", line);
      cli_printf(fd,
        "Available commands:\r\n"
        "  show bgp summary\r\n"
        "  show ip bgp\r\n"
        "  show ipv6 bgp\r\n"
        "  show bgp neighbors\r\n"
        "  show interface [<name>]\r\n"
        "  interface <name>\r\n"
        "  interface loopback <number>\r\n"
        "  show route\r\n"
        "  show route kernel\r\n"
        "  show route vrf [<name>]\r\n"
        "  show vrf [<name>]\r\n"
        "  show config\r\n"
        "  ip route <prefix>/<len> [via <nh>] [dev <if>] [table <id>] [kernel]\r\n"
        "  ipv6 route <prefix>/<len> [via <nh>] [dev <if>] [table <id>] [kernel]\r\n"
        "  no route <prefix>/<len> [table <id>] [kernel]\r\n"
        "  apply routes [table <id>]\r\n"
        "  write config [<path>]\r\n"
        "  clear bgp <neighbor-ip>\r\n"
        "  clear bgp all\r\n"
        "  exit | quit\r\n");
    }
  }

  return 0;
}

/* MARK: --- Client dispatch: submit completed line --- */

/* Called when the user presses Enter.  Dispatches the line and updates history. */
static int cli_submit_line(cli_client_t* cl)
{
  /* NUL-terminate for dispatch */
  cl->line[cl->line_len] = '\0';

  /* Echo newline (we are in server-echo mode) */
  cli_send(cl->fd, "\r\n", 2);

  /* Save non-empty lines to history before dispatch (dispatch may exit) */
  if (cl->line_len > 0) {
    hist_push(cl);
    cl->hist_idx = -1;
  }

  int rc = cli_dispatch(cl, g_cli.core, cl->line);

  /* Reset line buffer */
  cl->line_len = 0;

  return rc;
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
      cli_client_t* cl = &g_cli.clients[i];
      memset(cl, 0, sizeof(*cl));
      cl->fd       = fd;
      cl->hist_idx = -1;
      return cl;
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
  cl->line_len = 0;
}

/*
 * Per-character line-editor state machine.
 *
 * Reads all available bytes from the client fd and processes them one at a
 * time.  Returns -1 if the connection should be closed.
 */
static void on_cli_client_io(int fd, uint32_t events, void* arg)
{
  (void)events;
  (void)arg;
  cli_client_t* cl = find_client_by_fd(fd);
  if (!cl) return;

  uint8_t buf[256];
  for (;;) {
    ssize_t n = read(fd, buf, sizeof(buf));
    if (n < 0) {
      if (errno == EINTR)  continue;
      if (errno == EAGAIN || errno == EWOULDBLOCK) break;
      free_client(cl);
      return;
    }
    if (n == 0) {
      free_client(cl);
      return;
    }

    for (ssize_t i = 0; i < n; i++) {
      uint8_t b = buf[i];

      /* ── TELNET sub-negotiation absorber ─────────────────────────── */
      if (cl->in_sb) {
        /* Skip everything until IAC SE (255 240) */
        if (b == SE && i > 0 && buf[i-1] == IAC) cl->in_sb = 0;
        continue;
      }

      /* ── Escape sequence parser ───────────────────────────────────── */
      if (cl->esc_state == 1) {
        if (b == '[') { cl->esc_state = 2; continue; }
        /* Unknown escape — discard */
        cl->esc_state = 0;
        continue;
      }
      if (cl->esc_state == 2) {
        cl->esc_state = 0;
        if (b == 'A') { hist_prev(cl); continue; }  /* up   */
        if (b == 'B') { hist_next(cl); continue; }  /* down */
        /* Other CSI sequences (right/left/etc.) — ignore */
        continue;
      }

      /* ── TELNET IAC commands ──────────────────────────────────────── */
      if (b == IAC) {
        /* Peek at next byte if available */
        if (i + 1 < n) {
          uint8_t cmd = buf[i+1];
          if (cmd == SB) {
            cl->in_sb = 1;
            i++;          /* skip SB byte */
            continue;
          }
          if (cmd == WILL || cmd == WONT || cmd == DO || cmd == DONT) {
            i += 2;       /* skip cmd + option */
            continue;
          }
          if (cmd == IAC) {
            /* Escaped 0xFF — treat as literal (rare, ignore) */
            i++;
            continue;
          }
        }
        /* IAC without a following byte yet — just skip */
        continue;
      }

      /* ── Normal character processing ─────────────────────────────── */
      if (b == 0x1b) {           /* ESC */
        cl->esc_state = 1;
        continue;
      }
      if (b == '\t') {           /* Tab — first-word completion */
        tab_complete(cl);
        continue;
      }
      if (b == '\r' || b == '\n') {  /* Enter */
        if (cli_submit_line(cl) < 0) {
          free_client(cl);
          return;
        }
        /* Redraw prompt after command dispatch */
        redraw_line(cl);
        continue;
      }
      if (b == 0x7f || b == 0x08) {  /* DEL / Backspace */
        do_backspace(cl);
        continue;
      }
      if (b == 0x03) {           /* Ctrl-C — clear line */
        do_clear_line(cl);
        continue;
      }
      if (b == 0x04 && cl->line_len == 0) {  /* Ctrl-D on empty — close */
        cli_send(cl->fd, "Bye.\r\n", 6);
        free_client(cl);
        return;
      }
      if (b == 0x15) {           /* Ctrl-U — kill line */
        /* Erase however many chars are on screen */
        while (cl->line_len > 0) do_backspace(cl);
        continue;
      }

      /* Printable character — only accept if buffer has room */
      if (isprint((int)b) && cl->line_len < CLI_LINE_MAX - 1) {
        cl->line[cl->line_len++] = (char)b;
        /* Echo the character back */
        cli_send(cl->fd, (char*)&b, 1);
      }
    }
  }
}

/* TELNET negotiation sequence sent to each new client:
 *   IAC WILL ECHO          — server echoes characters
 *   IAC WILL SGA           — suppress go-ahead (full-duplex)
 *
 * Simplified sequence: removed LINEMODE negotiation which causes
 * compatibility issues with various telnet clients. Modern clients
 * default to character-at-a-time mode anyway.
 */
static const uint8_t TELNET_INIT[] = {
  IAC, WILL, OPT_ECHO,
  IAC, WILL, OPT_SGA,
};

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

  /* Send TELNET negotiation to enable character-at-a-time mode */
  cli_send(cfd, (const char*)TELNET_INIT, sizeof(TELNET_INIT));

  /* Welcome banner + initial prompt with proper line endings */
  static const char BANNER[] =
    "\r\n"
    "Welcome to bgpd VTY\r\n"
    "Type 'exit' or 'quit' to disconnect, TAB for verb completion.\r\n"
    "\r\n";
  cli_send(cfd, BANNER, sizeof(BANNER) - 1);

  /* Send initial prompt */
  cli_send(cfd, CLI_PROMPT, strlen(CLI_PROMPT));
}

/* MARK: --- Public API --- */

int cli_start(bgp_core_t* c, event_loop_t* loop, const char* sockpath)
{
  if (!c || !loop || !sockpath) return -1;

  /* Initialise client slots */
  for (int i = 0; i < CLI_MAX_CLIENTS; i++) {
    g_cli.clients[i].fd    = -1;
    g_cli.clients[i].line_len = 0;
    g_cli.clients[i].hist_idx = -1;
  }

  g_cli.core       = c;
  g_cli.loop       = loop;
  g_cli.listen_fd  = -1;
  strncpy(g_cli.sockpath, sockpath, sizeof(g_cli.sockpath) - 1);
  g_cli.sockpath[sizeof(g_cli.sockpath) - 1] = '\0';

  /* Parse socket specification: "unix:/path" or "host:port" */
  const char* socket_addr = sockpath;
  int use_unix = 1;

  if (strncmp(sockpath, "unix:", 5) == 0) {
    /* Explicit UNIX socket: skip "unix:" prefix */
    socket_addr = sockpath + 5;
    use_unix = 1;
  } else if (strchr(sockpath, ':') && strncmp(sockpath, "/", 1) != 0) {
    /* Looks like host:port (contains ':' but not a path) */
    use_unix = 0;
    socket_addr = sockpath;
  }
  /* Otherwise treat as path to UNIX socket (backward compatible) */

  int lfd = -1;

  if (use_unix) {
    /* UNIX domain socket */
    /* Remove any stale socket file */
    (void)unlink(socket_addr);

    lfd = socket(AF_UNIX, SOCK_STREAM, 0);
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
    strncpy(sa.sun_path, socket_addr, sizeof(sa.sun_path) - 1);

    if (bind(lfd, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
      log_msg(BGP_LOG_ERROR, "cli_start: bind(%s): %s", socket_addr, strerror(errno));
      close(lfd);
      return -1;
    }

    if (listen(lfd, 4) < 0) {
      log_msg(BGP_LOG_ERROR, "cli_start: listen: %s", strerror(errno));
      close(lfd);
      (void)unlink(socket_addr);
      return -1;
    }

    /* Non-blocking */
    fl = fcntl(lfd, F_GETFL, 0);
    if (fl >= 0) (void)fcntl(lfd, F_SETFL, fl | O_NONBLOCK);

    if (ev_add_fd(loop, lfd, EV_READ, on_cli_accept, NULL) < 0) {
      log_msg(BGP_LOG_ERROR, "cli_start: ev_add_fd failed");
      close(lfd);
      (void)unlink(socket_addr);
      return -1;
    }

    g_cli.listen_fd = lfd;
    log_msg(BGP_LOG_INFO, "VTY CLI listening on unix:%s", socket_addr);
  } else {
    /* TCP socket (host:port) */
    /* Parse host and port from "host:port" or "[ipv6]:port" format */
    char host_str[256];
    char port_str[32];
    const char* colon = NULL;

    /* Handle IPv6 addresses in brackets: [::1]:5000 */
    if (socket_addr[0] == '[') {
      const char* bracket_end = strchr(socket_addr, ']');
      if (!bracket_end) {
        log_msg(BGP_LOG_ERROR, "cli_start: missing closing bracket in IPv6 address: %s", socket_addr);
        return -1;
      }
      colon = strchr(bracket_end, ':');
      if (!colon) {
        log_msg(BGP_LOG_ERROR, "cli_start: missing port in IPv6 address: %s", socket_addr);
        return -1;
      }
      /* Extract IPv6 address without brackets */
      size_t host_len = bracket_end - socket_addr - 1;
      if (host_len >= sizeof(host_str)) {
        log_msg(BGP_LOG_ERROR, "cli_start: IPv6 address too long");
        return -1;
      }
      strncpy(host_str, socket_addr + 1, host_len);
      host_str[host_len] = '\0';
    } else {
      /* Handle IPv4 or hostname: 127.0.0.1:5000 or localhost:5000 */
      colon = strchr(socket_addr, ':');
      if (!colon) {
        log_msg(BGP_LOG_ERROR, "cli_start: invalid TCP format (expected host:port): %s", socket_addr);
        return -1;
      }
      size_t host_len = colon - socket_addr;
      if (host_len >= sizeof(host_str)) {
        log_msg(BGP_LOG_ERROR, "cli_start: hostname too long");
        return -1;
      }
      strncpy(host_str, socket_addr, host_len);
      host_str[host_len] = '\0';
    }

    /* Extract port part */
    const char* port_ptr = colon + 1;
    strncpy(port_str, port_ptr, sizeof(port_str) - 1);
    port_str[sizeof(port_str) - 1] = '\0';

    /* Validate port number */
    int port = atoi(port_str);
    if (port <= 0 || port > 65535) {
      log_msg(BGP_LOG_ERROR, "cli_start: invalid port number: %s", port_str);
      return -1;
    }

    /* Use getaddrinfo for hostname resolution (supports both IPv4 and IPv6) */
    struct addrinfo hints, *results = NULL, *p = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;      /* Allow both IPv4 and IPv6 */
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;      /* For binding, not connecting */

    int status = getaddrinfo(host_str[0] ? host_str : NULL, port_str, &hints, &results);
    if (status != 0) {
      log_msg(BGP_LOG_ERROR, "cli_start: getaddrinfo(%s:%s): %s",
              host_str, port_str, gai_strerror(status));
      return -1;
    }

    /* Try to bind to the first available address */
    for (p = results; p != NULL; p = p->ai_next) {
      lfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
      if (lfd < 0) continue;

      /* Allow reuse of local addresses */
      int opt = 1;
      (void)setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

      /* FD_CLOEXEC */
      int fl = fcntl(lfd, F_GETFD, 0);
      if (fl >= 0) (void)fcntl(lfd, F_SETFD, fl | FD_CLOEXEC);

      if (bind(lfd, p->ai_addr, p->ai_addrlen) == 0) {
        /* Binding succeeded */
        break;
      }

      /* Binding failed, try next address */
      close(lfd);
      lfd = -1;
    }

    freeaddrinfo(results);

    if (lfd < 0) {
      log_msg(BGP_LOG_ERROR, "cli_start: bind(%s:%s): failed", host_str, port_str);
      return -1;
    }

    if (listen(lfd, 4) < 0) {
      log_msg(BGP_LOG_ERROR, "cli_start: listen: %s", strerror(errno));
      close(lfd);
      return -1;
    }

    /* Non-blocking */
    int fl = fcntl(lfd, F_GETFL, 0);
    if (fl >= 0) (void)fcntl(lfd, F_SETFL, fl | O_NONBLOCK);

    if (ev_add_fd(loop, lfd, EV_READ, on_cli_accept, NULL) < 0) {
      log_msg(BGP_LOG_ERROR, "cli_start: ev_add_fd failed");
      close(lfd);
      return -1;
    }

    g_cli.listen_fd = lfd;
    log_msg(BGP_LOG_INFO, "VTY CLI listening on TCP %s:%s", host_str, port_str);
  }

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
