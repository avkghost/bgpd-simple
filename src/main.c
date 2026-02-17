// src/main.c
#include "bgp/bgp.h"
#include "bgp/cfg.h"
#include "bgp/log.h"
#include "bgp/dbg.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>   // getopt

static void usage(const char* argv0){
  fprintf(stderr,
    "Usage: %s -f <config> [-v|-vv]\n"
    "  -f <file>   config file path\n"
    "  -v          info logs\n"
    "  -vv         debug logs\n",
    argv0);
}

int main(int argc, char** argv){
  const char* cfg_path = NULL;
  int vcount = 0;

  for(;;){
    int c = getopt(argc, argv, "f:v");
    if(c == -1) break;
    switch(c){
      case 'f':
        cfg_path = optarg;
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

  bgp_run(g);

  // If bgp_start() blocks and runs the loop, we never reach here until shutdown.
  // If bgp_start() returns immediately, then your library needs a bgp_run() API.
  bgp_destroy(g);
  return 0;
}
