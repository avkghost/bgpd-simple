#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>

#include "bgp/attrs.h"

#define BGP_MARKER_LEN 16
#define BGP_MAX_MSG    4096

typedef enum {
  BGP_MSG_OPEN         = 1,
  BGP_MSG_UPDATE       = 2,
  BGP_MSG_NOTIFICATION = 3,
  BGP_MSG_KEEPALIVE    = 4,
  BGP_MSG_ROUTE_REFRESH = 5  /* RFC 2918 */
} bgp_msg_type_t;

typedef struct {
  uint8_t  marker[BGP_MARKER_LEN];
  uint16_t len;
  uint8_t  type;
} __attribute__((packed)) bgp_hdr_t;

typedef struct {
  uint8_t        version;     // 4
  uint16_t       my_as;       // legacy 2-byte ASN (23456 if AS4 is used)
  uint16_t       hold_time;
  struct in_addr bgp_id;
  uint8_t        opt_len;
  // optional parameters follow
} __attribute__((packed)) bgp_open_fixed_t;

typedef struct {
  uint16_t code;
  uint16_t subcode;
} bgp_notification_t;

/* Forward-declare peer type without pulling peer.h (avoids include cycles). */
typedef struct bgp_peer bgp_peer_t;

/* OPEN / KEEPALIVE / NOTIFICATION */
int bgp_send_open(bgp_peer_t* p);
int bgp_send_keepalive(bgp_peer_t* p);
int bgp_send_notification(bgp_peer_t* p, uint8_t code, uint8_t subcode);

/* Route-Refresh (RFC 2918): send RR for the given AFI/SAFI, or 0/0 for all */
int bgp_send_route_refresh(bgp_peer_t* p, uint16_t afi, uint8_t safi);

/* RX: reads/parses full messages and triggers FSM events */
int bgp_rx_process(bgp_peer_t* p);

/* Classic IPv4 UPDATE (NLRI in main UPDATE field) */
int peer_send_update4(bgp_peer_t* p,
                      const struct in_addr* pfx, uint8_t plen,
                      const bgp_attrs_t* a,
                      bool withdraw);

/* MP-BGP UPDATE (MP_REACH_NLRI / MP_UNREACH_NLRI) */
int peer_send_mp(bgp_peer_t* p,
                 uint16_t afi, uint8_t safi,
                 const bgp_attrs_t* attrs,
                 const uint8_t* nh, uint8_t nh_len,
                 const uint8_t* nlri, uint16_t nlri_len,
                 bool withdraw);
