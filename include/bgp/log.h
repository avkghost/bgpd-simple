#pragma once
#include <stdarg.h>

/*
 * Logging subsystem
 *
 * Supports:
 *  - log levels
 *  - foreground logging to stderr
 *  - daemon mode logging via syslog
 */

typedef enum {
  BGP_LOG_DEBUG = 0,
  BGP_LOG_INFO  = 1,
  BGP_LOG_WARN  = 2,
  BGP_LOG_ERROR = 3
} log_level_t;

/* Set minimum log level */
void log_set_level(log_level_t lvl);

/* Enable/disable daemon mode (uses syslog when enabled) */
void log_set_daemon(int daemonize);

/* Main logging function */
void log_msg(log_level_t lvl, const char* fmt, ...);
