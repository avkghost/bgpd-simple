// src/main.c
#include "bgp/bgp.h"
#include "bgp/cfg.h"
#include "bgp/log.h"
#include "bgp/dbg.h"
#include "bgp/signals.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>   // getopt
#include <signal.h>

static void usage(const char* argv0){
  fprintf(stderr,
    "Usage: %s -f <config> [-v|-vv] [-l <listen>]\n"
    "  -f <file>      config file path\n"
    "  -v             info logs\n"
    "  -vv            debug logs\n"
    "  -l <listen>    CLI socket: unix:/path/to/socket or host:port\n"
    "                 (default: unix:/tmp/bgpd.sock)\n",
    argv0);
}

int main(int argc, char** argv){
  const char* cfg_path = NULL;
  const char* cli_listen = "/tmp/bgpd.sock";  // Default to UNIX socket in /tmp
  int vcount = 0;

  for(;;){
    int c = getopt(argc, argv, "f:l:v");
    if(c == -1) break;
    switch(c){
      case 'f':
        cfg_path = optarg;
        break;
      case 'l':
        cli_listen = optarg;
        break;
      case 'v':
        vcount++;
        break;
      default:
        usage(argv[0]);
        return 2;
    }
  }

  if(!cfg_path){
    usage(argv[0]);
    return 2;
  }

  // log level
  if(vcount >= 2) log_set_level(BGP_LOG_DEBUG);
  else if(vcount >= 1) log_set_level(BGP_LOG_INFO);
  else log_set_level(BGP_LOG_WARN);

  bgp_config_t cfg;
  memset(&cfg, 0, sizeof(cfg));

  if(bgp_load_config(&cfg, cfg_path) < 0){
    log_msg(BGP_LOG_ERROR, "Failed to load config: %s", cfg_path);
    return 1;
  }

  /* Store CLI listen configuration from command-line argument */
  strncpy(cfg.cli_listen, cli_listen, sizeof(cfg.cli_listen) - 1);
  cfg.cli_listen[sizeof(cfg.cli_listen) - 1] = '\0';

  bgp_global_t* g = bgp_create();
  if(!g){
    log_msg(BGP_LOG_ERROR, "bgp_create() failed");
    return 1;
  }

  // NOTE:
  // - We do NOT touch g->core, g->loop, etc. (bgp_global_t is intentionally opaque)
  // - We do NOT allocate any big buffers in main.
  // - bgp_start() should create peers and run the event loop (or schedule start).
  //
  // If your bgp_start() implementation does NOT call ev_run() internally,
  // then add a bgp_run(g) API in bgp.h and call it here (recommended).
  if(bgp_start(g, &cfg, /*daemonize*/ false) < 0){
    log_msg(BGP_LOG_ERROR, "bgp_start() failed");
    bgp_destroy(g);
    return 1;
  }

  /* ── Initialize signal handling ────────────────────────────────── */
  void* loop = bgp_get_event_loop(g);
  if(!loop){
    log_msg(BGP_LOG_ERROR, "bgp_get_event_loop() returned NULL");
    bgp_destroy(g);
    return 1;
  }

  if(bgp_signals_init(loop) < 0){
    log_msg(BGP_LOG_WARN, "signal handling initialization failed - continuing anyway");
  } else {
    /* Register standard signal handlers */
    bgp_signal_register(SIGTERM, bgp_on_sigterm, loop);
    bgp_signal_register(SIGHUP, bgp_on_sighup, (void*)g);
    bgp_signal_register(SIGUSR1, bgp_on_sigusr1, (void*)g);
    bgp_signal_register(SIGUSR2, bgp_on_sigusr2, (void*)g);

    log_msg(BGP_LOG_INFO, "Signal handlers registered:");
    log_msg(BGP_LOG_INFO, "  SIGTERM  - Graceful shutdown");
    log_msg(BGP_LOG_INFO, "  SIGHUP   - Configuration reload (framework ready)");
    log_msg(BGP_LOG_INFO, "  SIGUSR1  - Debug dump (implemented)");
    log_msg(BGP_LOG_INFO, "  SIGUSR2  - Stats dump (implemented)");
  }

  bgp_run(g);

  /* ── Cleanup ────────────────────────────────────────────────────── */
  bgp_signals_cleanup();
  bgp_destroy(g);
  return 0;
}
