// src/fsm.c

#include "bgp/fsm.h"
#include "bgp/peer.h"
#include "bgp/bgp.h"
#include "bgp/msg.h"
#include "bgp/event.h"
#include "bgp/sock.h"
#include "bgp/log.h"
#include "bgp/core.h"

#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#ifndef EV_READ
#define EV_READ  0x01u
#endif
#ifndef EV_WRITE
#define EV_WRITE 0x02u
#endif

static void stop_timers(bgp_peer_t* p){
  if(p->keepalive_timer_id > 0){
    (void)ev_del_timer(p->loop, p->keepalive_timer_id);
    p->keepalive_timer_id = 0;
  }
  if(p->hold_timer_id > 0){
    (void)ev_del_timer(p->loop, p->hold_timer_id);
    p->hold_timer_id = 0;
  }
}

static void hold_expire_cb(void* arg){
  bgp_peer_t* p = (bgp_peer_t*)arg;
  if(!p) return;
  log_msg(BGP_LOG_WARN, "Hold timer expired for %s", inet_ntoa(p->addr));
  bgp_fsm_event(p, BGP_EVT_HOLD_EXPIRE);
}

static void keepalive_cb(void* arg){
  bgp_peer_t* p = (bgp_peer_t*)arg;
  if(!p) return;
  if(p->st != BGP_ESTABLISHED) return;
  (void)bgp_send_keepalive(p);
}

const char* bgp_state_str(bgp_state_t s){
  switch(s){
    case BGP_IDLE:        return "Idle";
    case BGP_CONNECT:     return "Connect";
    case BGP_ACTIVE:      return "Active";
    case BGP_OPENSENT:    return "OpenSent";
    case BGP_OPENCONFIRM: return "OpenConfirm";
    case BGP_ESTABLISHED: return "Established";
    default:              return "?";
  }
}

static void gr_stale_expire_cb(void* arg){
  bgp_peer_t* p = (bgp_peer_t*)arg;
  if(!p) return;
  log_msg(BGP_LOG_INFO, "GR stale timer expired for %s — flushing stale routes",
          inet_ntoa(p->addr));
  p->gr_stale_active = false;
  p->gr_stale_timer_id = 0;
  /* Withdraw all routes from this peer from the local RIB.
   * We delegate back to core (core_on_peer_down handles bulk withdraw). */
  if(p->core) core_on_peer_down(p->core, p);
}

static void enter_idle(bgp_peer_t* p){
  if(p->fd >= 0){
    (void)ev_del_fd(p->loop, p->fd);
    close(p->fd);
    p->fd = -1;
  }
  stop_timers(p);
  p->rxlen = 0;
  p->st = BGP_IDLE;

  /* Graceful Restart: if peer advertised GR capability hold stale routes
   * for gr_time seconds before purging them from the RIB. */
  if(p->caps.graceful_restart && p->caps.gr_time > 0 && !p->gr_stale_active){
    p->gr_stale_active = true;
    p->gr_stale_timer_id = ev_add_timer(p->loop,
                                        (uint64_t)p->caps.gr_time * 1000ULL,
                                        false, gr_stale_expire_cb, p);
    log_msg(BGP_LOG_INFO, "GR: holding stale routes for %s (%us)",
            inet_ntoa(p->addr), p->caps.gr_time);
  } else if(!p->caps.graceful_restart){
    /* No GR capability — immediately purge routes from this peer */
    if(p->core) core_on_peer_down(p->core, p);
  }
}

static void reset_hold_timer(bgp_peer_t* p){
  if(!p || p->st != BGP_ESTABLISHED) return;

  uint16_t hold = p->negotiated_hold ? p->negotiated_hold : p->local_hold;
  if(hold == 0) return;

  if(p->hold_timer_id > 0){
    (void)ev_del_timer(p->loop, p->hold_timer_id);
    p->hold_timer_id = 0;
  }

  // one-shot hold timer, refreshed on RX
  p->hold_timer_id = ev_add_timer(p->loop, (uint64_t)hold * 1000ULL, false, hold_expire_cb, p);
}

void bgp_peer_on_rx_message(bgp_peer_t* p){
  reset_hold_timer(p);
}

static void start_established_timers(bgp_peer_t* p){
  stop_timers(p);

  uint16_t hold = p->negotiated_hold ? p->negotiated_hold : p->local_hold;
  uint16_t ka   = p->local_keepalive ? p->local_keepalive : (hold ? (uint16_t)(hold / 3) : 0);

  if(ka > 0){
    p->keepalive_timer_id = ev_add_timer(p->loop, (uint64_t)ka * 1000ULL, true, keepalive_cb, p);
  }

  // start hold as one-shot; it’ll be refreshed by RX
  if(hold > 0){
    p->hold_timer_id = ev_add_timer(p->loop, (uint64_t)hold * 1000ULL, false, hold_expire_cb, p);
  }
}

static void reconnect_cb(void* arg){
  bgp_peer_t* p = (bgp_peer_t*)arg;
  if(!p) return;

  // Only reconnect if we’re still idle/active (avoid double connect storms)
  if(p->st != BGP_IDLE && p->st != BGP_ACTIVE) return;

  bgp_fsm_event(p, BGP_EVT_START);
}

static void schedule_reconnect(bgp_peer_t* p){
  // fixed delay reconnect
  (void)ev_add_timer(p->loop, 3000, false, reconnect_cb, p);
}

static void on_sock_io(int fd, uint32_t events, void* arg){
  bgp_peer_t* p = (bgp_peer_t*)arg;
  (void)fd;
  if(!p) return;

  if(p->st == BGP_CONNECT && (events & EV_WRITE)){
    int err = 0;
    socklen_t elen = sizeof(err);
    if(getsockopt(p->fd, SOL_SOCKET, SO_ERROR, &err, &elen) < 0) err = errno;

    if(err != 0){
      log_msg(BGP_LOG_WARN, "Connect error to %s: %s", inet_ntoa(p->addr), strerror(err));
      bgp_fsm_event(p, BGP_EVT_TCP_FAIL);
      return;
    }

    log_msg(BGP_LOG_INFO, "TCP connected to %s", inet_ntoa(p->addr));

    (void)ev_mod_fd(p->loop, p->fd, EV_READ, on_sock_io, p);

    if(bgp_send_open(p) < 0){
      bgp_fsm_event(p, BGP_EVT_TCP_FAIL);
      return;
    }

    p->st = BGP_OPENSENT;
    return;
  }

  if(events & EV_READ){
    int rc = bgp_rx_process(p);

    // rc == -2 means: received NOTIFICATION and FSM already handled it
    if(rc == -2){
      return;
    }
    if(rc < 0){
      bgp_fsm_event(p, BGP_EVT_TCP_FAIL);
      return;
    }
  }
}

static void enter_connect(bgp_peer_t* p){
  p->fd = sock_connect_nonblock(p->addr, BGP_PORT);
  if(p->fd < 0){
    log_msg(BGP_LOG_WARN, "Connect failed to %s: %s", inet_ntoa(p->addr), strerror(errno));
    p->st = BGP_ACTIVE;
    schedule_reconnect(p);
    return;
  }

  if(ev_add_fd(p->loop, p->fd, EV_READ | EV_WRITE, on_sock_io, p) < 0){
    close(p->fd);
    p->fd = -1;
    p->st = BGP_ACTIVE;
    schedule_reconnect(p);
    return;
  }

  p->st = BGP_CONNECT;
}

void bgp_fsm_init(bgp_peer_t* p){
  if(!p) return;
  p->st = BGP_IDLE;
  p->fd = -1;
  p->rxlen = 0;
  p->keepalive_timer_id = 0;
  p->hold_timer_id = 0;
  p->gr_stale_timer_id = 0;
  p->gr_stale_active   = false;
}

/*
 * Called when an inbound TCP connection has been accepted for this peer.
 * Transitions the peer from IDLE/ACTIVE to OPENSENT by sending our OPEN.
 */
void bgp_fsm_accept(bgp_peer_t* p, int fd){
  if(!p || fd < 0) return;

  /* If there's an existing connection, close it first */
  if(p->fd >= 0){
    (void)ev_del_fd(p->loop, p->fd);
    close(p->fd);
    p->fd = -1;
  }

  p->fd = fd;
  (void)sock_set_nonblock(p->fd);
  (void)sock_set_nodelay(p->fd);

  if(ev_add_fd(p->loop, p->fd, EV_READ, on_sock_io, p) < 0){
    close(p->fd);
    p->fd = -1;
    return;
  }

  if(bgp_send_open(p) < 0){
    bgp_fsm_event(p, BGP_EVT_TCP_FAIL);
    return;
  }

  log_msg(BGP_LOG_INFO, "Passive TCP accepted from %s", inet_ntoa(p->addr));
  p->st = BGP_OPENSENT;
}

void bgp_fsm_event(bgp_peer_t* p, bgp_event_t ev){
  if(!p) return;

  switch(p->st){
    case BGP_IDLE:
      if(ev == BGP_EVT_START){
        enter_connect(p);
      }
      break;

    case BGP_CONNECT:
      if(ev == BGP_EVT_TCP_FAIL){
        enter_idle(p);
        schedule_reconnect(p);
      }
      break;

    case BGP_ACTIVE:
      if(ev == BGP_EVT_START){
        enter_connect(p);
      }
      break;

    case BGP_OPENSENT:
      if(ev == BGP_EVT_RX_OPEN){
        (void)bgp_send_keepalive(p);
        p->st = BGP_OPENCONFIRM;
      } else if(ev == BGP_EVT_TCP_FAIL || ev == BGP_EVT_RX_NOTIFICATION){
        enter_idle(p);
        schedule_reconnect(p);
      }
      break;

    case BGP_OPENCONFIRM:
      if(ev == BGP_EVT_RX_KEEPALIVE){
        p->st = BGP_ESTABLISHED;
        log_msg(BGP_LOG_INFO, "BGP Established with %s", inet_ntoa(p->addr));
        start_established_timers(p);

        // trigger initial advertisement
        if(p->core) core_on_established(p->core, p);
      } else if(ev == BGP_EVT_TCP_FAIL || ev == BGP_EVT_RX_NOTIFICATION){
        enter_idle(p);
        schedule_reconnect(p);
      }
      break;

    case BGP_ESTABLISHED:
      if(ev == BGP_EVT_HOLD_EXPIRE || ev == BGP_EVT_TCP_FAIL || ev == BGP_EVT_RX_NOTIFICATION){
        enter_idle(p);
        schedule_reconnect(p);
      }
      break;

    default:
      enter_idle(p);
      schedule_reconnect(p);
      break;
  }
}
