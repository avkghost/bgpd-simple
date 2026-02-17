#include "bgp/mpls.h"
#include "bgp/log.h"
#include <linux/rtnetlink.h>
#include <linux/lwtunnel.h>
#include <linux/mpls_iptunnel.h>
#include <linux/mpls.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

static int nl_send_req(struct nlmsghdr* nlh){
  int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
  if(fd < 0) return -1;

  struct sockaddr_nl sa = {0};
  sa.nl_family = AF_NETLINK;
  if(bind(fd, (struct sockaddr*)&sa, sizeof(sa)) < 0){ close(fd); return -1; }

  struct sockaddr_nl da = {0};
  da.nl_family = AF_NETLINK;

  struct iovec iov = { .iov_base = nlh, .iov_len = (size_t)nlh->nlmsg_len };
  struct msghdr msg = {0};
  msg.msg_name = &da;
  msg.msg_namelen = sizeof(da);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  if(sendmsg(fd, &msg, 0) < 0){ close(fd); return -1; }

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

static struct rtattr* addattr_nest(struct nlmsghdr* n, int maxlen, int type){
  int len = RTA_LENGTH(0);
  int newlen = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);
  if(newlen > maxlen) return NULL;
  struct rtattr* rta = (struct rtattr*)((char*)n + NLMSG_ALIGN(n->nlmsg_len));
  rta->rta_type = type;
  rta->rta_len = len;
  n->nlmsg_len = (uint32_t)newlen;
  return rta;
}

static void addattr_nest_end(struct nlmsghdr* n, struct rtattr* nest){
  if(!nest) return;
  nest->rta_len = (unsigned short)((char*)n + NLMSG_ALIGN(n->nlmsg_len) - (char*)nest);
}

/*
int nl_route_delete_v4_table(struct in_addr pfx, uint8_t plen, int table){
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
*/

int nl_route_replace_v4_mpls_encap(struct in_addr pfx, uint8_t plen,
                                   struct in_addr nh,
                                   const uint32_t* labels, int label_count,
                                   int table)
{
  if(label_count <= 0 || label_count > 8) { errno = EINVAL; return -1; }

  char buf[1024];
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

  // Set encap type MPLS
  uint16_t etype = LWTUNNEL_ENCAP_MPLS;
  addattr_l(n, (int)sizeof(buf), RTA_ENCAP_TYPE, &etype, sizeof(etype));

  // RTA_ENCAP is a nested blob. For MPLS, kernel expects MPLS_IPTUNNEL_DST attribute containing
  // an array of struct mpls_label (network order).
  struct rtattr* encap = addattr_nest(n, (int)sizeof(buf), RTA_ENCAP);
  if(!encap) { errno = ENOBUFS; return -1; }

  struct mpls_label stack[8];
  memset(stack, 0, sizeof(stack));

  for(int i=0;i<label_count;i++){
    // encode label with BOS on last
    uint32_t entry = (labels[i] & 0xFFFFF) << MPLS_LS_LABEL_SHIFT;
    if(i == label_count-1) entry |= (1u << MPLS_LS_S_SHIFT);
    // TTL left 0 => kernel may fill; you can set MPLS_LS_TTL_SHIFT too
    stack[i].entry = htonl(entry);
  }

  addattr_l(n, (int)sizeof(buf), MPLS_IPTUNNEL_DST, stack, (int)(label_count * (int)sizeof(stack[0])));
  addattr_nest_end(n, encap);

  return nl_send_req(n);
}

// AF_MPLS route: label -> via inet nh, outlabel stack
static void put_mpls_label_u32(uint8_t out[4], uint32_t label){
  // AF_MPLS RTA_DST expects 4-byte "struct mpls_label" entry (network order bits)
  uint32_t entry = (label & 0xFFFFF) << MPLS_LS_LABEL_SHIFT;
  entry |= (1u << MPLS_LS_S_SHIFT);
  uint32_t be = htonl(entry);
  memcpy(out, &be, 4);
}

int nl_mpls_route_replace(uint32_t in_label,
                          struct in_addr nh,
                          const uint32_t* out_labels, int out_label_count)
{
  char buf[1024];
  memset(buf, 0, sizeof(buf));

  struct nlmsghdr* n = (struct nlmsghdr*)buf;
  n->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
  n->nlmsg_type = RTM_NEWROUTE;
  n->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;

  struct rtmsg* r = (struct rtmsg*)NLMSG_DATA(n);
  r->rtm_family = AF_MPLS;
  r->rtm_table = RT_TABLE_MAIN;
  r->rtm_protocol = RTPROT_BOOT;
  r->rtm_scope = RT_SCOPE_UNIVERSE;
  r->rtm_type = RTN_UNICAST;
  r->rtm_dst_len = 20; // MPLS label bits

  uint8_t dst[4];
  put_mpls_label_u32(dst, in_label);
  addattr_l(n, (int)sizeof(buf), RTA_DST, dst, sizeof(dst));

  // via inet next-hop
  addattr_l(n, (int)sizeof(buf), RTA_VIA,
            &(struct { uint16_t family; struct in_addr addr; }){ .family = AF_INET, .addr = nh },
            (int)(sizeof(uint16_t) + sizeof(struct in_addr)));

  // out labels (swap / push); if empty => PHP behavior depends on kernel; keep single label common
  if(out_labels && out_label_count > 0){
    struct mpls_label stack[8];
    if(out_label_count > 8) { errno = EINVAL; return -1; }
    memset(stack,0,sizeof(stack));
    for(int i=0;i<out_label_count;i++){
      uint32_t entry = (out_labels[i] & 0xFFFFF) << MPLS_LS_LABEL_SHIFT;
      if(i == out_label_count-1) entry |= (1u << MPLS_LS_S_SHIFT);
      stack[i].entry = htonl(entry);
    }
    addattr_l(n, (int)sizeof(buf), RTA_NEWDST, stack, out_label_count*(int)sizeof(stack[0]));
  }

  return nl_send_req(n);
}

int nl_mpls_route_delete(uint32_t in_label){
  char buf[512];
  memset(buf, 0, sizeof(buf));

  struct nlmsghdr* n = (struct nlmsghdr*)buf;
  n->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
  n->nlmsg_type = RTM_DELROUTE;
  n->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

  struct rtmsg* r = (struct rtmsg*)NLMSG_DATA(n);
  r->rtm_family = AF_MPLS;
  r->rtm_table = RT_TABLE_MAIN;
  r->rtm_protocol = RTPROT_BOOT;
  r->rtm_scope = RT_SCOPE_UNIVERSE;
  r->rtm_type = RTN_UNICAST;
  r->rtm_dst_len = 20;

  uint8_t dst[4];
  put_mpls_label_u32(dst, in_label);
  addattr_l(n, (int)sizeof(buf), RTA_DST, dst, sizeof(dst));

  return nl_send_req(n);
}
