#include "bgp/interface.h"
#include "bgp/log.h"
#include <string.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>

int nl_interface_dump(sys_interface_cb_t cb, void* arg)
{
  if (!cb)
    return -1;

  struct ifaddrs* ifaddr = NULL;
  if (getifaddrs(&ifaddr) < 0) {
    log_msg(BGP_LOG_ERROR, "getifaddrs failed");
    return -1;
  }

  /* Enumerate interfaces using getifaddrs */
  sys_interface_t ifaces[256];
  int iface_count = 0;
  memset(ifaces, 0, sizeof(ifaces));

  for (struct ifaddrs* ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr == NULL)
      continue;

    /* Find or create interface entry */
    int idx = -1;
    for (int i = 0; i < iface_count; i++) {
      if (strcmp(ifaces[i].name, ifa->ifa_name) == 0) {
        idx = i;
        break;
      }
    }

    if (idx == -1 && iface_count < 256) {
      idx = iface_count++;
      strncpy(ifaces[idx].name, ifa->ifa_name, sizeof(ifaces[idx].name) - 1);
      ifaces[idx].index = if_nametoindex(ifa->ifa_name);

      if (ifa->ifa_flags & IFF_UP)
        ifaces[idx].flags |= IF_UP;
      if (ifa->ifa_flags & IFF_RUNNING)
        ifaces[idx].flags |= IF_RUNNING;
      if (ifa->ifa_flags & IFF_LOOPBACK)
        ifaces[idx].flags |= IF_LOOPBACK;
      if (ifa->ifa_flags & IFF_BROADCAST)
        ifaces[idx].flags |= IF_BROADCAST;
      if (ifa->ifa_flags & IFF_POINTOPOINT)
        ifaces[idx].flags |= IF_POINTOPOINT;
      if (ifa->ifa_flags & IFF_MULTICAST)
        ifaces[idx].flags |= IF_MULTICAST;

      ifaces[idx].mtu = 1500; /* Default MTU; could query via sysctl */
    }

    if (idx >= 0) {
      /* Parse addresses */
      if (ifa->ifa_addr->sa_family == AF_INET) {
        struct sockaddr_in* sin = (struct sockaddr_in*)ifa->ifa_addr;
        ifaces[idx].addr_v4 = sin->sin_addr;

        if (ifa->ifa_netmask) {
          struct sockaddr_in* mask = (struct sockaddr_in*)ifa->ifa_netmask;
          uint32_t m = ntohl(mask->sin_addr.s_addr);
          ifaces[idx].plen_v4 = __builtin_popcount(m);
        }
      } else if (ifa->ifa_addr->sa_family == AF_INET6) {
        struct sockaddr_in6* sin6 = (struct sockaddr_in6*)ifa->ifa_addr;
        ifaces[idx].addr_v6 = sin6->sin6_addr;
        ifaces[idx].plen_v6 = 64; /* Default; could query */
      }
    }
  }

  freeifaddrs(ifaddr);

  /* Invoke callbacks */
  for (int i = 0; i < iface_count; i++) {
    if (cb(&ifaces[i], arg) != 0)
      break;
  }

  return 0;
}

int nl_interface_set_up(const char* name, int up)
{
  (void)name;
  (void)up;
  log_msg(BGP_LOG_ERROR, "nl_interface_set_up not implemented on this platform");
  return -1;
}

int nl_interface_set_addr_v4(const char* name, struct in_addr addr, uint8_t plen)
{
  (void)name;
  (void)addr;
  (void)plen;
  log_msg(BGP_LOG_ERROR, "nl_interface_set_addr_v4 not implemented on this platform");
  return -1;
}

int nl_interface_set_addr_v6(const char* name, struct in6_addr addr, uint8_t plen)
{
  (void)name;
  (void)addr;
  (void)plen;
  log_msg(BGP_LOG_ERROR, "nl_interface_set_addr_v6 not implemented on this platform");
  return -1;
}

int nl_interface_set_mtu(const char* name, uint32_t mtu)
{
  (void)name;
  (void)mtu;
  log_msg(BGP_LOG_ERROR, "nl_interface_set_mtu not implemented on this platform");
  return -1;
}

int nl_interface_create_loopback(const char* loopback_name)
{
  (void)loopback_name;
  log_msg(BGP_LOG_ERROR, "nl_interface_create_loopback not implemented on this platform");
  return -1;
}
