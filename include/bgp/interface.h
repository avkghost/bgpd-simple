#pragma once
#include <stdint.h>
#include <netinet/in.h>

/**
 * @file interface.h
 * @brief Network interface management API for bgpd.
 *
 * Provides platform-neutral interface enumeration, address management,
 * and configuration tracking.
 */

/**
 * Interface flags (Linux IFF_* constants).
 */
#define IF_UP          0x0001   /* Interface is up */
#define IF_RUNNING     0x0040   /* Interface is running */
#define IF_LOOPBACK    0x0008   /* Loopback interface */
#define IF_BROADCAST   0x0002   /* Broadcast capable */
#define IF_POINTOPOINT 0x0010   /* Point-to-point link */
#define IF_MULTICAST   0x1000   /* Multicast capable */
#define IF_LOWER_UP    0x10000  /* Interface L1 up (Linux RTM_NEWLINK) */
#define IF_DORMANT     0x20000  /* Interface dormant (Linux) */

/**
 * System interface snapshot returned by nl_interface_dump() callbacks.
 * Represents a single interface with its current state from the kernel.
 */
typedef struct {
  char          name[16];              /* Interface name (eth0, eth1, lo0, etc.) */
  uint32_t      index;                 /* Interface index (ifindex) */
  uint32_t      flags;                 /* IF_UP, IF_LOOPBACK, IF_RUNNING, etc. */
  uint32_t      mtu;                   /* Maximum transmission unit (bytes) */
  uint8_t       mac[6];                /* MAC address (6 bytes) */

  struct in_addr  addr_v4;             /* IPv4 address (0.0.0.0 if not set) */
  uint8_t         plen_v4;             /* IPv4 prefix length (0-32) */

  struct in6_addr addr_v6;             /* IPv6 address (:: if not set) */
  uint8_t         plen_v6;             /* IPv6 prefix length (0-128) */

  int routing_priority;                /* Metric/cost for routing (-1 = default) */
  char description[64];                /* Interface description */
} sys_interface_t;

/**
 * Interface configuration storage (extends system interface state).
 * Used to store user-configured interface parameters.
 */
typedef struct {
  char name[16];                /* Interface name (eth0, eth1, lo0, etc.) */
  uint32_t mtu;                 /* MTU in bytes */
  uint8_t shutdown;             /* 1 = admin down, 0 = up */
  char description[64];         /* User-configured description */
  int routing_priority;         /* Metric/cost for routing */

  struct in_addr addr_v4;       /* IPv4 address */
  uint8_t plen_v4;              /* IPv4 prefix length */

  struct in6_addr addr_v6;      /* IPv6 address */
  uint8_t plen_v6;              /* IPv6 prefix length */
} interface_cfg_t;

/**
 * Callback invoked once per interface during enumeration.
 * Return 0 to continue iteration, non-zero to stop.
 */
typedef int (*sys_interface_cb_t)(const sys_interface_t* iface, void* arg);

/**
 * Dump all network interfaces from the kernel.
 * Queries both link state (RTM_GETLINK) and addresses (RTM_GETADDR).
 * Invokes cb(interface, arg) for each interface found.
 *
 * @param cb   Callback function invoked for each interface
 * @param arg  Opaque user data passed to callback
 * @return 0 on success, -1 on error
 */
int nl_interface_dump(sys_interface_cb_t cb, void* arg);

/**
 * Set interface administrative state.
 *
 * @param name      Interface name (e.g., "eth0")
 * @param up        1 to bring up, 0 to bring down
 * @return 0 on success, -1 on error
 */
int nl_interface_set_up(const char* name, int up);

/**
 * Assign IPv4 address to interface.
 *
 * @param name      Interface name
 * @param addr      IPv4 address
 * @param plen      Prefix length (0-32)
 * @return 0 on success, -1 on error
 */
int nl_interface_set_addr_v4(const char* name, struct in_addr addr, uint8_t plen);

/**
 * Assign IPv6 address to interface.
 *
 * @param name      Interface name
 * @param addr      IPv6 address
 * @param plen      Prefix length (0-128)
 * @return 0 on success, -1 on error
 */
int nl_interface_set_addr_v6(const char* name, struct in6_addr addr, uint8_t plen);

/**
 * Set interface MTU.
 *
 * @param name      Interface name
 * @param mtu       MTU size in bytes (typically 1500)
 * @return 0 on success, -1 on error
 */
int nl_interface_set_mtu(const char* name, uint32_t mtu);

/**
 * Create virtual loopback interface.
 * On Linux, creates a new loopback interface (lo0, lo1, lo2, etc.)
 *
 * @param loopback_name  Name for loopback interface (e.g., "lo1", "lo2")
 * @return 0 on success, -1 on error
 */
int nl_interface_create_loopback(const char* loopback_name);
