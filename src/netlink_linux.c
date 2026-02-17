#include "bgp/netlink.h"
#include "bgp/log.h"
#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <net/if.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

static int nl_send_req(struct nlmsghdr* nlh){
  int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
  if(fd < 0) return -1;

  struct sockaddr_nl sa = {0};
  sa.nl_family = AF_NETLINK;

  if(bind(fd, (struct sockaddr*)&sa, sizeof(sa)) < 0){
    close(fd); return -1;
  }

  struct sockaddr_nl da = {0};
  da.nl_family = AF_NETLINK;

  struct iovec iov = { .iov_base = nlh, .iov_len = (size_t)nlh->nlmsg_len };
  struct msghdr msg = {0};
  msg.msg_name = &da;
  msg.msg_namelen = sizeof(da);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  if(sendmsg(fd, &msg, 0) < 0){
    close(fd); return -1;
  }

  // read ACK
  char buf[4096];
  ssize_t n = recv(fd, buf, sizeof(buf), 0);
  close(fd);
  if(n < 0) return -1;

  struct nlmsghdr* r = (struct nlmsghdr*)buf;
  if(r->nlmsg_type == NLMSG_ERROR){
    struct nlmsgerr* e = (struct nlmsgerr*)NLMSG_DATA(r);
    if(e->error != 0){
      errno = -e->error;
      return -1;
    }
  }
  return 0;
}

static void addattr_l(struct nlmsghdr* n, int maxlen, int type, const void* data, int alen){
  int len = RTA_LENGTH(alen);
  int newlen = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);
  if(newlen > maxlen) return;
  struct rtattr* rta = (struct rtattr*)((char*)n + NLMSG_ALIGN(n->nlmsg_len));
  rta->rta_type = type;
  rta->rta_len = len;
  memcpy(RTA_DATA(rta), data, (size_t)alen);
  n->nlmsg_len = (uint32_t)newlen;
}

int nl_route_replace_v4(struct in_addr pfx, uint8_t plen, struct in_addr nh, int table){
  char buf[512];
  memset(buf, 0, sizeof(buf));

  struct nlmsghdr* n = (struct nlmsghdr*)buf;
  n->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
  n->nlmsg_type = RTM_NEWROUTE;
  n->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;

  struct rtmsg* r = (struct rtmsg*)NLMSG_DATA(n);
  r->rtm_family = AF_INET;
  r->rtm_table = (uint8_t)table;
  r->rtm_protocol = RTPROT_BOOT;
  r->rtm_scope = RT_SCOPE_UNIVERSE;
  r->rtm_type = RTN_UNICAST;
  r->rtm_dst_len = plen;

  addattr_l(n, (int)sizeof(buf), RTA_DST, &pfx, sizeof(pfx));
  addattr_l(n, (int)sizeof(buf), RTA_GATEWAY, &nh, sizeof(nh));

  return nl_send_req(n);
}

int nl_route_delete_v4(struct in_addr pfx, uint8_t plen, int table){
  char buf[512];
  memset(buf, 0, sizeof(buf));

  struct nlmsghdr* n = (struct nlmsghdr*)buf;
  n->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
  n->nlmsg_type = RTM_DELROUTE;
  n->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

  struct rtmsg* r = (struct rtmsg*)NLMSG_DATA(n);
  r->rtm_family = AF_INET;
  r->rtm_table = (uint8_t)table;
  r->rtm_protocol = RTPROT_BOOT;
  r->rtm_scope = RT_SCOPE_UNIVERSE;
  r->rtm_type = RTN_UNICAST;
  r->rtm_dst_len = plen;

  addattr_l(n, (int)sizeof(buf), RTA_DST, &pfx, sizeof(pfx));
  return nl_send_req(n);
}

int nl_route_dump_v4(sys_route4_cb_t cb, void* arg)
{
  if (!cb) return -1;

  int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
  if (fd < 0) return -1;

  struct sockaddr_nl sa;
  memset(&sa, 0, sizeof(sa));
  sa.nl_family = AF_NETLINK;
  if (bind(fd, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
    close(fd); return -1;
  }

  /* Send RTM_GETROUTE dump request */
  struct {
    struct nlmsghdr nlh;
    struct rtmsg    rtm;
  } req;
  memset(&req, 0, sizeof(req));
  req.nlh.nlmsg_len   = NLMSG_LENGTH(sizeof(struct rtmsg));
  req.nlh.nlmsg_type  = RTM_GETROUTE;
  req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  req.rtm.rtm_family  = AF_INET;

  struct sockaddr_nl da;
  memset(&da, 0, sizeof(da));
  da.nl_family = AF_NETLINK;

  struct iovec iov = { &req, req.nlh.nlmsg_len };
  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  msg.msg_name    = &da;
  msg.msg_namelen = sizeof(da);
  msg.msg_iov     = &iov;
  msg.msg_iovlen  = 1;

  if (sendmsg(fd, &msg, 0) < 0) {
    close(fd); return -1;
  }

  /* Read multi-part reply */
  char* rxbuf = malloc(65536);
  if (!rxbuf) { close(fd); return -1; }

  int ret = 0;
  for (;;) {
    ssize_t n = recv(fd, rxbuf, 65536, 0);
    if (n < 0) {
      if (errno == EINTR) continue;
      ret = -1; break;
    }
    if (n == 0) break;

    struct nlmsghdr* nlh = (struct nlmsghdr*)rxbuf;
    for (; NLMSG_OK(nlh, (uint32_t)n); nlh = NLMSG_NEXT(nlh, n)) {
      if (nlh->nlmsg_type == NLMSG_DONE) goto done;
      if (nlh->nlmsg_type == NLMSG_ERROR) { ret = -1; goto done; }
      if (nlh->nlmsg_type != RTM_NEWROUTE) continue;

      struct rtmsg* rtm = (struct rtmsg*)NLMSG_DATA(nlh);
      /* Only IPv4 unicast routes */
      if (rtm->rtm_family != AF_INET) continue;
      if (rtm->rtm_type   != RTN_UNICAST) continue;

      sys_route4_t r;
      memset(&r, 0, sizeof(r));
      r.plen  = rtm->rtm_dst_len;
      r.table = rtm->rtm_table;
      r.proto = rtm->rtm_protocol;

      int rta_len = (int)(nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*rtm)));
      struct rtattr* rta = RTM_RTA(rtm);
      for (; RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len)) {
        switch (rta->rta_type) {
          case RTA_DST:
            memcpy(&r.dst, RTA_DATA(rta), 4);
            break;
          case RTA_GATEWAY:
            memcpy(&r.gw, RTA_DATA(rta), 4);
            break;
          case RTA_PRIORITY:
            memcpy(&r.metric, RTA_DATA(rta), sizeof(r.metric));
            break;
          case RTA_OIF: {
            unsigned idx;
            memcpy(&idx, RTA_DATA(rta), sizeof(idx));
            if_indextoname(idx, r.ifname);
            break;
          }
          default: break;
        }
      }

      if (cb(&r, arg) != 0) goto done;
    }
  }
done:
  free(rxbuf);
  close(fd);
  return ret;
}
