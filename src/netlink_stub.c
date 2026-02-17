#include "bgp/netlink.h"
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <net/if.h>
#include <net/route.h>
#include <sys/sysctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

int nl_route_replace_v4(struct in_addr pfx, uint8_t plen, struct in_addr nh, int table){
  (void)pfx; (void)plen; (void)nh; (void)table;
  errno = ENOSYS;
  return -1;
}

int nl_route_delete_v4(struct in_addr pfx, uint8_t plen, int table){
  (void)pfx; (void)plen; (void)table;
  errno = ENOSYS;
  return -1;
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
