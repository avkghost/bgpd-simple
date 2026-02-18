/*
 * Platform-neutral route programming interface.
 *
 * Provides portable abstraction over netlink (Linux) and routing socket (BSD/macOS).
 * Supports IPv4, IPv6, and MPLS route operations.
 */

#ifndef BGP_PLATFORM_ROUTE_H
#define BGP_PLATFORM_ROUTE_H

#include <netinet/in.h>
#include <stdint.h>

/* IPv4 route: add/replace route in kernel FIB */
int route_add_v4(struct in_addr dst, uint8_t plen,
                 struct in_addr gw, const char* ifname, int table);

/* IPv4 route: delete route from kernel FIB */
int route_delete_v4(struct in_addr dst, uint8_t plen, int table);

/* IPv6 route: add/replace route in kernel FIB */
int route_add_v6(struct in6_addr dst, uint8_t plen,
                 struct in6_addr gw, const char* ifname, int table);

/* IPv6 route: delete route from kernel FIB */
int route_delete_v6(struct in6_addr dst, uint8_t plen, int table);

/* MPLS route: add/replace MPLS label route */
int route_add_mpls(uint32_t label, struct in_addr nh, int table);

/* MPLS route: delete MPLS label route */
int route_delete_mpls(uint32_t label, int table);

/* System route information (for dumping kernel FIB) */
typedef struct {
  struct in_addr dst;
  struct in_addr gw;
  uint8_t plen;
  char ifname[16];
  int table;
  uint8_t proto;  /* RTPROT_* (Linux) or equivalent */
} sys_route_v4_t;

typedef struct {
  struct in6_addr dst;
  struct in6_addr gw;
  uint8_t plen;
  char ifname[16];
  int table;
  uint8_t proto;
} sys_route_v6_t;

/* Dump IPv4 routes from kernel FIB — calls callback for each route */
typedef int (*route_callback_v4)(const sys_route_v4_t* route, void* arg);
int route_dump_v4(route_callback_v4 cb, void* arg);

/* Dump IPv6 routes from kernel FIB — calls callback for each route */
typedef int (*route_callback_v6)(const sys_route_v6_t* route, void* arg);
int route_dump_v6(route_callback_v6 cb, void* arg);

#endif /* BGP_PLATFORM_ROUTE_H */
