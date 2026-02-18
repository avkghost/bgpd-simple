#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>

/* Install/replace an IPv4 route via gateway nexthop. */
int nl_route_replace_v4(struct in_addr pfx, uint8_t plen, struct in_addr nh, int table);

/*
 * Install/replace an IPv4 route via a named interface (with optional gateway).
 * If nh.s_addr == 0, installs a directly-connected/interface-only route.
 * ifname must be non-NULL and non-empty.
 */
int nl_route_replace_v4_dev(struct in_addr pfx, uint8_t plen,
                             struct in_addr nh, const char* ifname, int table);

int nl_route_delete_v4(struct in_addr pfx, uint8_t plen, int table);

/*
 * System route entry returned by nl_route_dump_v4().
 * Covers IPv4 unicast routes from the kernel FIB.
 */
typedef struct {
    struct in_addr dst;        /* destination prefix */
    uint8_t        plen;       /* prefix length */
    struct in_addr gw;         /* next-hop gateway (0.0.0.0 = directly connected) */
    uint32_t       table;      /* routing table ID */
    uint8_t        proto;      /* route origin (RTPROT_* on Linux, 0 on macOS) */
    uint32_t       metric;     /* route metric / priority */
    char           ifname[16]; /* output interface name */
} sys_route4_t;

/*
 * Callback invoked once per system route.
 * Return 0 to continue iteration, non-zero to stop.
 */
typedef int (*sys_route4_cb_t)(const sys_route4_t* r, void* arg);

/*
 * Dump all IPv4 unicast routes from the kernel.
 * Invokes cb(route, arg) for each entry.
 * Returns 0 on success, -1 on error.
 */
int nl_route_dump_v4(sys_route4_cb_t cb, void* arg);

/* ──────────────────────────────────────────────────────────────────────────── */
/* IPv6 ROUTE OPERATIONS */
/* ──────────────────────────────────────────────────────────────────────────── */

/* Install/replace an IPv6 route via gateway nexthop. */
int nl_route_replace_v6(struct in6_addr pfx, uint8_t plen, struct in6_addr nh, int table);

/*
 * Install/replace an IPv6 route via a named interface (with optional gateway).
 * If nh is all zeros (::), installs a directly-connected/interface-only route.
 * ifname must be non-NULL and non-empty.
 */
int nl_route_replace_v6_dev(struct in6_addr pfx, uint8_t plen,
                            struct in6_addr nh, const char* ifname, int table);

int nl_route_delete_v6(struct in6_addr pfx, uint8_t plen, int table);

/*
 * System route entry returned by nl_route_dump_v6().
 * Covers IPv6 unicast routes from the kernel FIB.
 */
typedef struct {
  struct in6_addr dst;       /* destination prefix */
  uint8_t plen;              /* prefix length */
  struct in6_addr gw;        /* next-hop gateway (:: = directly connected) */
  uint32_t table;            /* routing table ID */
  uint8_t proto;             /* route origin (RTPROT_* on Linux) */
  uint32_t metric;           /* route metric / priority */
  char ifname[16];           /* output interface name */
} sys_route6_t;

/*
 * Callback invoked once per IPv6 system route.
 * Return 0 to continue iteration, non-zero to stop.
 */
typedef int (*sys_route6_cb_t)(const sys_route6_t* r, void* arg);

/*
 * Dump all IPv6 unicast routes from the kernel.
 * Invokes cb(route, arg) for each entry.
 * Returns 0 on success, -1 on error.
 */
int nl_route_dump_v6(sys_route6_cb_t cb, void* arg);
