#include "bgp/netlink.h"
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <net/if.h>
#include <net/route.h>
#include <sys/sysctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

/* ── BSD routing-socket helpers ──────────────────────────────────────────── */

/*
 * Build a netmask sockaddr_in from a prefix length.
 * The BSD kernel uses a compact form: only the significant bytes are included.
 */
static struct sockaddr_in
plen_to_mask_sa(uint8_t plen)
{
  struct sockaddr_in sa;
  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  if (plen == 0) {
    sa.sin_addr.s_addr = 0;
    sa.sin_len = (uint8_t)sizeof(sa);
  } else {
    sa.sin_addr.s_addr = htonl(~((1u << (32 - plen)) - 1));
    sa.sin_len = (uint8_t)sizeof(sa);
  }
  return sa;
}

/*
 * Send a RTM_ADD or RTM_DELETE message via a BSD routing socket.
 * gateway: may be NULL for interface-only routes.
 * ifindex: set to the output interface index (0 = not specified).
 */
static int
rt_msg_send(int type, struct in_addr dst, uint8_t plen,
            const struct in_addr* gw, unsigned ifindex)
{
  /* Routing socket messages are built as a concatenation of rt_msghdr
   * followed by a series of sockaddrs indexed by RTAX_*. */
  struct {
    struct rt_msghdr  hdr;
    struct sockaddr_in dst_sa;
    struct sockaddr_in gw_sa;
    struct sockaddr_in mask_sa;
  } req;

  memset(&req, 0, sizeof(req));

  req.dst_sa.sin_family = AF_INET;
  req.dst_sa.sin_len    = sizeof(req.dst_sa);
  req.dst_sa.sin_addr   = dst;

  req.mask_sa = plen_to_mask_sa(plen);

  int addrs = RTA_DST | RTA_NETMASK;

  if (gw && gw->s_addr != 0) {
    req.gw_sa.sin_family = AF_INET;
    req.gw_sa.sin_len    = sizeof(req.gw_sa);
    req.gw_sa.sin_addr   = *gw;
    addrs |= RTA_GATEWAY;
  }

  req.hdr.rtm_msglen  = (uint16_t)sizeof(req);
  req.hdr.rtm_version = RTM_VERSION;
  req.hdr.rtm_type    = (uint8_t)type;
  req.hdr.rtm_addrs   = addrs;
  req.hdr.rtm_flags   = RTF_UP | RTF_STATIC;
  if (gw && gw->s_addr != 0)
    req.hdr.rtm_flags |= RTF_GATEWAY;
  req.hdr.rtm_index   = (unsigned short)ifindex;
  req.hdr.rtm_pid     = getpid();
  req.hdr.rtm_seq     = 1;
  (void)ifindex; /* index set in hdr above; kernel uses it for RTF_HOST routes */

  int s = socket(AF_ROUTE, SOCK_RAW, 0);
  if (s < 0) return -1;

  ssize_t n = write(s, &req, sizeof(req));
  close(s);
  return (n == (ssize_t)sizeof(req)) ? 0 : -1;
}

int nl_route_replace_v4(struct in_addr pfx, uint8_t plen, struct in_addr nh, int table)
{
  (void)table; /* BSD routing sockets don't support per-table routing easily */
  /* Try RTM_CHANGE first; if the route doesn't exist, fall back to RTM_ADD */
  if (rt_msg_send(RTM_CHANGE, pfx, plen, &nh, 0) < 0)
    return rt_msg_send(RTM_ADD, pfx, plen, &nh, 0);
  return 0;
}

int nl_route_replace_v4_dev(struct in_addr pfx, uint8_t plen,
                             struct in_addr nh, const char* ifname, int table)
{
  (void)table;
  if (!ifname || !ifname[0]) return -1;

  unsigned ifindex = if_nametoindex(ifname);
  if (ifindex == 0) { errno = ENODEV; return -1; }

  const struct in_addr* gw = (nh.s_addr != 0) ? &nh : NULL;

  if (rt_msg_send(RTM_CHANGE, pfx, plen, gw, ifindex) < 0)
    return rt_msg_send(RTM_ADD, pfx, plen, gw, ifindex);
  return 0;
}

int nl_route_delete_v4(struct in_addr pfx, uint8_t plen, int table)
{
  (void)table;
  struct in_addr zero = {0};
  return rt_msg_send(RTM_DELETE, pfx, plen, &zero, 0);
}

/*
 * macOS/BSD route dump using sysctl(NET_RT_DUMP).
 *
 * The kernel returns a packed array of routing socket messages
 * (struct rt_msghdr) each followed by a variable number of sockaddrs
 * encoded with RTAX_* indexes.  We decode only RTAX_DST, RTAX_GATEWAY,
 * and RTAX_NETMASK to build the sys_route4_t entries.
 */

/* Advance pointer to next sockaddr, respecting routing-socket alignment. */
static const struct sockaddr*
sa_next(const struct sockaddr* sa)
{
  size_t len = sa->sa_len ? sa->sa_len : sizeof(long);
  /* round up to sizeof(long) boundary */
  len = (len + sizeof(long) - 1) & ~(sizeof(long) - 1);
  return (const struct sockaddr*)((const char*)sa + len);
}

/* Count bits in a contiguous IPv4 netmask. */
static uint8_t
mask_to_plen(const struct sockaddr* sa)
{
  if (!sa || sa->sa_len < 4) return 0;
  /* sa_len for a netmask may be shorter than sizeof(sockaddr_in) */
  const uint8_t* p = (const uint8_t*)sa + 4; /* skip sa_len, sa_family, sin_port */
  int nbytes = (int)sa->sa_len - 4;
  if (nbytes <= 0) return 0;
  uint8_t bits = 0;
  for (int i = 0; i < nbytes; i++) {
    uint8_t b = p[i];
    while (b & 0x80) { bits++; b <<= 1; }
  }
  return bits;
}

int nl_route_dump_v4(sys_route4_cb_t cb, void* arg)
{
  if (!cb) return -1;

  /* Fetch the routing table dump via sysctl */
  int mib[6] = { CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_DUMP, 0 };
  size_t needed = 0;
  if (sysctl(mib, 6, NULL, &needed, NULL, 0) < 0) return -1;
  if (needed == 0) return 0;

  char* buf = malloc(needed);
  if (!buf) return -1;

  if (sysctl(mib, 6, buf, &needed, NULL, 0) < 0) {
    free(buf); return -1;
  }

  int ret = 0;
  const char* p   = buf;
  const char* end = buf + needed;

  while (p < end) {
    const struct rt_msghdr* rtm = (const struct rt_msghdr*)p;
    if (rtm->rtm_msglen < sizeof(*rtm)) break;

    /* Skip non-unicast, non-IPv4, and loopback/blackhole entries */
    if (rtm->rtm_version != RTM_VERSION) goto next;
    if (!(rtm->rtm_flags & RTF_UP))      goto next;
    if (rtm->rtm_flags & RTF_LLINFO)     goto next; /* ARP cache */

    /* Walk the sockaddrs that follow the rt_msghdr */
    const struct sockaddr* sa   = (const struct sockaddr*)(rtm + 1);
    const struct sockaddr* addrs[RTAX_MAX];
    memset(addrs, 0, sizeof(addrs));

    for (int i = 0; i < RTAX_MAX; i++) {
      if (!(rtm->rtm_addrs & (1 << i))) continue;
      if ((const char*)sa >= (const char*)rtm + rtm->rtm_msglen) break;
      addrs[i] = sa;
      sa = sa_next(sa);
    }

    /* Only handle IPv4 destinations */
    if (!addrs[RTAX_DST]) goto next;
    if (addrs[RTAX_DST]->sa_family != AF_INET) goto next;

    sys_route4_t r;
    memset(&r, 0, sizeof(r));

    /* Destination */
    const struct sockaddr_in* dst_sa =
        (const struct sockaddr_in*)addrs[RTAX_DST];
    r.dst = dst_sa->sin_addr;

    /* Prefix length from netmask */
    if (addrs[RTAX_NETMASK])
      r.plen = mask_to_plen(addrs[RTAX_NETMASK]);
    else
      r.plen = 32; /* host route */

    /* Gateway */
    if (addrs[RTAX_GATEWAY] &&
        addrs[RTAX_GATEWAY]->sa_family == AF_INET) {
      const struct sockaddr_in* gw_sa =
          (const struct sockaddr_in*)addrs[RTAX_GATEWAY];
      r.gw = gw_sa->sin_addr;
    }

    /* Interface name from interface index */
    if (rtm->rtm_index)
      if_indextoname((unsigned)rtm->rtm_index, r.ifname);

    r.metric = (uint32_t)rtm->rtm_rmx.rmx_hopcount;
    r.table  = 0;   /* BSD does not expose table IDs in the same way */
    r.proto  = 0;

    if (cb(&r, arg) != 0) { ret = 0; goto out; }

next:
    p += rtm->rtm_msglen;
  }

out:
  free(buf);
  return ret;
}

/* ──────────────────────────────────────────────────────────────────────────── */
/* IPv6 ROUTE OPERATIONS — BSD/MACOS STUBS */
/* ──────────────────────────────────────────────────────────────────────────── */

int nl_route_replace_v6(struct in6_addr pfx, uint8_t plen, struct in6_addr nh, int table)
{
  (void)pfx; (void)plen; (void)nh; (void)table;
  errno = ENOSYS;
  return -1;
}

int nl_route_replace_v6_dev(struct in6_addr pfx, uint8_t plen,
                            struct in6_addr nh, const char* ifname, int table)
{
  (void)pfx; (void)plen; (void)nh; (void)ifname; (void)table;
  errno = ENOSYS;
  return -1;
}

int nl_route_delete_v6(struct in6_addr pfx, uint8_t plen, int table)
{
  (void)pfx; (void)plen; (void)table;
  errno = ENOSYS;
  return -1;
}

int nl_route_dump_v6(sys_route6_cb_t cb, void* arg)
{
  (void)cb; (void)arg;
  errno = ENOSYS;
  return -1;
}
