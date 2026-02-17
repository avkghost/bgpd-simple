#pragma once
/**
 * @file cli.h
 * @brief VTY control-plane CLI over a UNIX-domain socket.
 *
 * Provides a Cisco-like show/clear interface for the running daemon.
 * Clients connect with: nc -U /var/run/bgpd.sock
 *
 * Supported commands:
 *   show bgp summary
 *   show ip bgp
 *   show bgp neighbors
 *   clear bgp <ip>
 *   clear bgp all
 *   exit / quit
 */

#include "bgp/core.h"
#include "bgp/event.h"

/**
 * @brief Start the VTY listener on a UNIX-domain socket.
 *
 * @param c        BGP core state (for RIB / peer inspection).
 * @param loop     Event loop to register the accept fd with.
 * @param sockpath Path for the UNIX socket (e.g. "/var/run/bgpd.sock").
 * @return 0 on success, -1 on error.
 */
int cli_start(bgp_core_t* c, event_loop_t* loop, const char* sockpath);

/**
 * @brief Remove the UNIX socket file and clean up.
 *
 * Call from bgp_stop() / atexit.
 */
void cli_stop(void);
