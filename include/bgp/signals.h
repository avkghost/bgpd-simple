#pragma once

#include <signal.h>
#include <stdint.h>

typedef struct bgp_signal_ctx bgp_signal_ctx_t;

/* Signal handler context - manages signal delivery to event loop */
typedef struct {
  uint32_t signum;      /* Signal number (SIGTERM, SIGHUP, etc.) */
  uint64_t count;       /* Number of times this signal was received */
  int handled;          /* Whether handler should process this signal */
} bgp_signal_info_t;

/**
 * Initialize signal handling system.
 * Must be called before bgp_run().
 * 
 * @param loop Event loop pointer (from bgp_global_t)
 * @return 0 on success, -1 on error
 */
int bgp_signals_init(void* loop);

/**
 * Register handler for a specific signal.
 * Signals are delivered via event loop, not synchronously.
 * 
 * @param signum Signal number (SIGTERM, SIGHUP, etc.)
 * @param callback Function to call when signal received
 * @param arg User data passed to callback
 * @return 0 on success, -1 on error
 */
typedef void (*bgp_signal_handler)(uint32_t signum, void* arg);
int bgp_signal_register(uint32_t signum, bgp_signal_handler callback, void* arg);

/**
 * Unregister signal handler.
 * 
 * @param signum Signal number to unregister
 * @return 0 on success, -1 if not registered
 */
int bgp_signal_unregister(uint32_t signum);

/**
 * Get signal statistics.
 * 
 * @param signum Signal number
 * @return Signal info or NULL if signal not tracked
 */
bgp_signal_info_t* bgp_signal_get_info(uint32_t signum);

/**
 * Cleanup signal handling system.
 * Call before exit.
 */
void bgp_signals_cleanup(void);

/* Standard signal handlers for BGP daemon */
void bgp_on_sigterm(uint32_t signum, void* arg);   /* Graceful shutdown */
void bgp_on_sighup(uint32_t signum, void* arg);    /* Config reload */
void bgp_on_sigusr1(uint32_t signum, void* arg);   /* Debug dump */
void bgp_on_sigusr2(uint32_t signum, void* arg);   /* Stats dump */

