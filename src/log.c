#include "bgp/log.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>

static log_level_t g_level = LOG_INFO;
static int g_daemon = 0;

static const char* level_str(log_level_t lvl){
  switch(lvl){
    case BGP_LOG_DEBUG: return "DEBUG";
    case BGP_LOG_INFO:  return "INFO";
    case BGP_LOG_WARN:  return "WARN";
    case BGP_LOG_ERROR: return "ERROR";
    default:        return "?";
  }
}

static int level_to_syslog(log_level_t lvl){
  switch(lvl){
    case BGP_LOG_DEBUG: return LOG_DEBUG;
    case BGP_LOG_INFO:  return LOG_INFO;
    case BGP_LOG_WARN:  return LOG_WARNING;
    case BGP_LOG_ERROR: return LOG_ERR;
    default:        return LOG_INFO;
  }
}

void log_set_level(log_level_t lvl){
  g_level = lvl;
}

void log_set_daemon(int daemonize){
  g_daemon = daemonize;
  if(g_daemon){
    openlog("bgpd", LOG_PID | LOG_NDELAY, LOG_DAEMON);
  }
}

void log_msg(log_level_t lvl, const char* fmt, ...){
  if(lvl < g_level) return;

  va_list ap;
  va_start(ap, fmt);

  if(g_daemon){
    // syslog path
    char buf[1024];
    vsnprintf(buf, sizeof(buf), fmt, ap);
    syslog(level_to_syslog(lvl), "%s", buf);
  } else {
    // stderr path with timestamp
    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);

    char ts[64];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm);

    flockfile(stderr);
    fprintf(stderr, "%s [%s] ", ts, level_str(lvl));
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    funlockfile(stderr);
  }

  va_end(ap);
}
