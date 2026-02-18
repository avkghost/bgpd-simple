#include "bgp/interface.h"
#include "bgp/log.h"
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <sys/socket.h>

/* Helper to add attributes to netlink message */
static void addattr_l(struct nlmsghdr* n, int maxlen, int type,
                      const void* data, int alen)
{
  struct rtattr* rta = (struct rtattr*)(((char*)(n)) + NLMSG_ALIGN(n->nlmsg_len));
  rta->rta_type = type;
  rta->rta_len = RTA_LENGTH(alen);
  if (rta->rta_len > (size_t)(maxlen - NLMSG_ALIGN(n->nlmsg_len)))
    return;
  memcpy(RTA_DATA(rta), data, alen);
  n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(rta->rta_len);
}

/* Parse RTM_GETLINK response attributes */
static void parse_link_attr(struct rtattr* attr, int len, sys_interface_t* iface)
{
  for (; RTA_OK(attr, len); attr = RTA_NEXT(attr, len)) {
    switch (attr->rta_type) {
    case IFLA_IFNAME:
      strncpy(iface->name, (const char*)RTA_DATA(attr), sizeof(iface->name) - 1);
      break;
    case IFLA_MTU:
      iface->mtu = *(uint32_t*)RTA_DATA(attr);
      break;
    case IFLA_ADDRESS:
      if (RTA_PAYLOAD(attr) == 6) {
        memcpy(iface->mac, RTA_DATA(attr), 6);
      }
      break;
    }
  }
}

/* Parse RTM_GETADDR response attributes */
static void parse_addr_attr(struct rtattr* attr, int len, int family, sys_interface_t* iface)
{
  for (; RTA_OK(attr, len); attr = RTA_NEXT(attr, len)) {
    switch (attr->rta_type) {
    case IFA_ADDRESS:
      if (family == AF_INET && RTA_PAYLOAD(attr) == 4) {
        memcpy(&iface->addr_v4, RTA_DATA(attr), 4);
      } else if (family == AF_INET6 && RTA_PAYLOAD(attr) == 16) {
        memcpy(&iface->addr_v6, RTA_DATA(attr), 16);
      }
      break;
    }
  }
}

int nl_interface_dump(sys_interface_cb_t cb, void* arg)
{
  if (!cb)
    return -1;

  int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
  if (sock < 0) {
    log_msg(BGP_LOG_ERROR, "Failed to create netlink socket: %s", strerror(errno));
    return -1;
  }

  struct sockaddr_nl local = {
    .nl_family = AF_NETLINK,
  };
  bind(sock, (struct sockaddr*)&local, sizeof(local));

  /* Dump interfaces (RTM_GETLINK) */
  struct {
    struct nlmsghdr h;
    struct ifinfomsg body;
  } req_link = {
    .h = {
      .nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
      .nlmsg_type = RTM_GETLINK,
      .nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
      .nlmsg_seq = 1,
    },
    .body = {
      .ifi_family = AF_UNSPEC,
    },
  };

  if (send(sock, &req_link, req_link.h.nlmsg_len, 0) < 0) {
    log_msg(BGP_LOG_ERROR, "Failed to send RTM_GETLINK: %s", strerror(errno));
    close(sock);
    return -1;
  }

  /* Store interface info as we receive it */
  sys_interface_t ifaces[256];
  int iface_count = 0;
  memset(ifaces, 0, sizeof(ifaces));

  char buf[4096];
  while (1) {
    ssize_t status = recvfrom(sock, buf, sizeof(buf), 0, NULL, NULL);
    if (status < 0) {
      log_msg(BGP_LOG_ERROR, "Failed to recv RTM_GETLINK: %s", strerror(errno));
      close(sock);
      return -1;
    }

    if (status == 0)
      break;

    struct nlmsghdr* h = (struct nlmsghdr*)buf;
    while (NLMSG_OK(h, (size_t)status)) {
      if (h->nlmsg_type == NLMSG_DONE)
        goto parse_addrs;
      if (h->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr* err = (struct nlmsgerr*)NLMSG_DATA(h);
        log_msg(BGP_LOG_ERROR, "RTM_GETLINK error: %s", strerror(-err->error));
        close(sock);
        return -1;
      }

      if (h->nlmsg_type == RTM_NEWLINK) {
        struct ifinfomsg* ifi = (struct ifinfomsg*)NLMSG_DATA(h);
        if (iface_count < 256) {
          sys_interface_t* iface = &ifaces[iface_count];
          iface->index = ifi->ifi_index;
          iface->flags = ifi->ifi_flags;

          int len = IFLA_PAYLOAD(h);
          parse_link_attr(IFLA_RTA(ifi), len, iface);

          iface_count++;
        }
      }

      h = NLMSG_NEXT(h, status);
    }
  }

parse_addrs:
  /* Dump interface addresses (RTM_GETADDR) */
  struct {
    struct nlmsghdr h;
    struct ifaddrmsg body;
  } req_addr = {
    .h = {
      .nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg)),
      .nlmsg_type = RTM_GETADDR,
      .nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
      .nlmsg_seq = 2,
    },
    .body = {
      .ifa_family = AF_UNSPEC,
    },
  };

  if (send(sock, &req_addr, req_addr.h.nlmsg_len, 0) < 0) {
    log_msg(BGP_LOG_ERROR, "Failed to send RTM_GETADDR: %s", strerror(errno));
    close(sock);
    return -1;
  }

  while (1) {
    ssize_t status = recvfrom(sock, buf, sizeof(buf), 0, NULL, NULL);
    if (status < 0) {
      log_msg(BGP_LOG_ERROR, "Failed to recv RTM_GETADDR: %s", strerror(errno));
      close(sock);
      return -1;
    }

    if (status == 0)
      break;

    struct nlmsghdr* h = (struct nlmsghdr*)buf;
    while (NLMSG_OK(h, (size_t)status)) {
      if (h->nlmsg_type == NLMSG_DONE)
        goto invoke_callbacks;
      if (h->nlmsg_type == NLMSG_ERROR)
        goto invoke_callbacks;

      if (h->nlmsg_type == RTM_NEWADDR) {
        struct ifaddrmsg* ifa = (struct ifaddrmsg*)NLMSG_DATA(h);

        /* Find matching interface by index */
        for (int i = 0; i < iface_count; i++) {
          if (ifaces[i].index == (uint32_t)ifa->ifa_index) {
            int len = IFA_PAYLOAD(h);
            parse_addr_attr(IFA_RTA(ifa), len, ifa->ifa_family, &ifaces[i]);
            ifaces[i].plen_v4 = (ifa->ifa_family == AF_INET) ? ifa->ifa_prefixlen : 0;
            ifaces[i].plen_v6 = (ifa->ifa_family == AF_INET6) ? ifa->ifa_prefixlen : 0;
            break;
          }
        }
      }

      h = NLMSG_NEXT(h, status);
    }
  }

invoke_callbacks:
  /* Invoke callback for each interface */
  for (int i = 0; i < iface_count; i++) {
    if (cb(&ifaces[i], arg) != 0)
      break;
  }

  close(sock);
  return 0;
}

int nl_interface_set_up(const char* name, int up)
{
  if (!name)
    return -1;

  int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
  if (sock < 0)
    return -1;

  struct sockaddr_nl local = {
    .nl_family = AF_NETLINK,
  };
  bind(sock, (struct sockaddr*)&local, sizeof(local));

  /* Get current interface state */
  struct {
    struct nlmsghdr h;
    struct ifinfomsg body;
  } req = {
    .h = {
      .nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
      .nlmsg_type = RTM_GETLINK,
      .nlmsg_flags = NLM_F_REQUEST,
      .nlmsg_seq = 1,
    },
    .body = {
      .ifi_family = AF_UNSPEC,
    },
  };

  addattr_l(&req.h, sizeof(req), IFLA_IFNAME, (void*)name, strlen(name) + 1);

  if (send(sock, &req, req.h.nlmsg_len, 0) < 0) {
    close(sock);
    return -1;
  }

  /* Parse response to get current flags */
  char buf[1024];
  ssize_t status = recvfrom(sock, buf, sizeof(buf), 0, NULL, NULL);
  if (status < 0) {
    close(sock);
    return -1;
  }

  uint32_t current_flags = 0;
  struct nlmsghdr* h = (struct nlmsghdr*)buf;
  if (h->nlmsg_type == RTM_NEWLINK) {
    struct ifinfomsg* ifi = (struct ifinfomsg*)NLMSG_DATA(h);
    current_flags = ifi->ifi_flags;
  }

  /* Set interface flags */
  struct {
    struct nlmsghdr h;
    struct ifinfomsg body;
  } set_req = {
    .h = {
      .nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
      .nlmsg_type = RTM_SETLINK,
      .nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK,
      .nlmsg_seq = 2,
    },
    .body = {
      .ifi_family = AF_UNSPEC,
      .ifi_flags = up ? (current_flags | IFF_UP) : (current_flags & ~IFF_UP),
      .ifi_change = IFF_UP,
    },
  };

  addattr_l(&set_req.h, sizeof(set_req), IFLA_IFNAME, (void*)name, strlen(name) + 1);

  if (send(sock, &set_req, set_req.h.nlmsg_len, 0) < 0) {
    close(sock);
    return -1;
  }

  /* Read ACK */
  status = recvfrom(sock, buf, sizeof(buf), 0, NULL, NULL);
  close(sock);

  return (status >= 0) ? 0 : -1;
}

int nl_interface_set_addr_v4(const char* name, struct in_addr addr, uint8_t plen)
{
  if (!name || plen > 32)
    return -1;

  int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
  if (sock < 0)
    return -1;

  struct sockaddr_nl local = {
    .nl_family = AF_NETLINK,
  };
  bind(sock, (struct sockaddr*)&local, sizeof(local));

  /* Get interface index */
  unsigned int ifindex = if_nametoindex(name);
  if (ifindex == 0) {
    close(sock);
    return -1;
  }

  struct {
    struct nlmsghdr h;
    struct ifaddrmsg body;
    char attrs[256];
  } req = {
    .h = {
      .nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg)),
      .nlmsg_type = RTM_NEWADDR,
      .nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE,
      .nlmsg_seq = 1,
    },
    .body = {
      .ifa_family = AF_INET,
      .ifa_prefixlen = plen,
      .ifa_index = ifindex,
      .ifa_scope = RT_SCOPE_UNIVERSE,
    },
  };

  addattr_l(&req.h, sizeof(req), IFA_LOCAL, &addr, 4);
  addattr_l(&req.h, sizeof(req), IFA_ADDRESS, &addr, 4);

  if (send(sock, &req, req.h.nlmsg_len, 0) < 0) {
    close(sock);
    return -1;
  }

  char buf[1024];
  ssize_t status = recvfrom(sock, buf, sizeof(buf), 0, NULL, NULL);
  close(sock);

  return (status >= 0) ? 0 : -1;
}

int nl_interface_set_addr_v6(const char* name, struct in6_addr addr, uint8_t plen)
{
  if (!name || plen > 128)
    return -1;

  int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
  if (sock < 0)
    return -1;

  struct sockaddr_nl local = {
    .nl_family = AF_NETLINK,
  };
  bind(sock, (struct sockaddr*)&local, sizeof(local));

  unsigned int ifindex = if_nametoindex(name);
  if (ifindex == 0) {
    close(sock);
    return -1;
  }

  struct {
    struct nlmsghdr h;
    struct ifaddrmsg body;
    char attrs[256];
  } req = {
    .h = {
      .nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg)),
      .nlmsg_type = RTM_NEWADDR,
      .nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE,
      .nlmsg_seq = 1,
    },
    .body = {
      .ifa_family = AF_INET6,
      .ifa_prefixlen = plen,
      .ifa_index = ifindex,
      .ifa_scope = RT_SCOPE_UNIVERSE,
    },
  };

  addattr_l(&req.h, sizeof(req), IFA_LOCAL, &addr, 16);
  addattr_l(&req.h, sizeof(req), IFA_ADDRESS, &addr, 16);

  if (send(sock, &req, req.h.nlmsg_len, 0) < 0) {
    close(sock);
    return -1;
  }

  char buf[1024];
  ssize_t status = recvfrom(sock, buf, sizeof(buf), 0, NULL, NULL);
  close(sock);

  return (status >= 0) ? 0 : -1;
}

int nl_interface_set_mtu(const char* name, uint32_t mtu)
{
  if (!name || mtu < 68)
    return -1;

  int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
  if (sock < 0)
    return -1;

  struct sockaddr_nl local = {
    .nl_family = AF_NETLINK,
  };
  bind(sock, (struct sockaddr*)&local, sizeof(local));

  struct {
    struct nlmsghdr h;
    struct ifinfomsg body;
    char attrs[256];
  } req = {
    .h = {
      .nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
      .nlmsg_type = RTM_SETLINK,
      .nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK,
      .nlmsg_seq = 1,
    },
    .body = {
      .ifi_family = AF_UNSPEC,
    },
  };

  addattr_l(&req.h, sizeof(req), IFLA_IFNAME, (void*)name, strlen(name) + 1);
  addattr_l(&req.h, sizeof(req), IFLA_MTU, &mtu, sizeof(mtu));

  if (send(sock, &req, req.h.nlmsg_len, 0) < 0) {
    close(sock);
    return -1;
  }

  char buf[1024];
  ssize_t status = recvfrom(sock, buf, sizeof(buf), 0, NULL, NULL);
  close(sock);

  return (status >= 0) ? 0 : -1;
}

int nl_interface_create_loopback(const char* loopback_name)
{
  if (!loopback_name)
    return -1;

  int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
  if (sock < 0)
    return -1;

  struct sockaddr_nl local = {
    .nl_family = AF_NETLINK,
  };
  bind(sock, (struct sockaddr*)&local, sizeof(local));

  struct {
    struct nlmsghdr h;
    struct ifinfomsg body;
    char attrs[256];
  } req = {
    .h = {
      .nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
      .nlmsg_type = RTM_NEWLINK,
      .nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL,
      .nlmsg_seq = 1,
    },
    .body = {
      .ifi_family = AF_UNSPEC,
      .ifi_type = ARPHRD_LOOPBACK,
    },
  };

  addattr_l(&req.h, sizeof(req), IFLA_IFNAME, (void*)loopback_name, strlen(loopback_name) + 1);

  if (send(sock, &req, req.h.nlmsg_len, 0) < 0) {
    close(sock);
    return -1;
  }

  char buf[1024];
  ssize_t status = recvfrom(sock, buf, sizeof(buf), 0, NULL, NULL);
  close(sock);

  if (status < 0)
    return -1;

  struct nlmsghdr* h = (struct nlmsghdr*)buf;
  if (h->nlmsg_type == NLMSG_ERROR) {
    struct nlmsgerr* err = (struct nlmsgerr*)NLMSG_DATA(h);
    if (err->error != 0)
      return -1;
  }

  return 0;
}
