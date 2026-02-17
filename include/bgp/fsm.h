#pragma once
#include <stdint.h>
#include <stdbool.h>

typedef enum {
  BGP_IDLE=0, BGP_CONNECT, BGP_ACTIVE, BGP_OPENSENT, BGP_OPENCONFIRM, BGP_ESTABLISHED
} bgp_state_t;

typedef enum {
  BGP_EVT_START=1,
  BGP_EVT_TCP_CONNECTED,
  BGP_EVT_TCP_FAIL,
  BGP_EVT_RX_OPEN,
  BGP_EVT_RX_KEEPALIVE,
  BGP_EVT_RX_NOTIFICATION,
  BGP_EVT_HOLD_EXPIRE,
  BGP_EVT_KEEPALIVE_TIMER,
  BGP_EVT_STOP
} bgp_event_t;

struct bgp_peer;

void bgp_fsm_init(struct bgp_peer* p);
void bgp_fsm_event(struct bgp_peer* p, bgp_event_t ev);
const char* bgp_state_str(bgp_state_t s);

/* Accept an inbound (passive) TCP connection for a configured peer */
void bgp_fsm_accept(struct bgp_peer* p, int fd);

// Called by msg.c on any received BGP message to refresh hold timer.
void bgp_peer_on_rx_message(struct bgp_peer* p);
