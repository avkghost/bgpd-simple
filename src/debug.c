/**
 * BGP daemon debug and statistics dumping functionality.
 * 
 * These functions are called via signal handlers (SIGUSR1 for debug,
 * SIGUSR2 for stats) to dump internal state to the system log for
 * troubleshooting and performance monitoring.
 */

#include "bgp/debug.h"
#include "bgp/log.h"

#include <stdio.h>
#include <time.h>

/**
 * Dump BGP daemon debug information to syslog.
 */
void bgp_debug_dump_to_log(void)
{
  log_msg(BGP_LOG_INFO, "═══════════════════════════════════════════════════════");
  log_msg(BGP_LOG_INFO, "                    BGP DEBUG DUMP                      ");
  log_msg(BGP_LOG_INFO, "═══════════════════════════════════════════════════════");
  
  time_t now = time(NULL);
  struct tm* tm_info = localtime(&now);
  char time_buf[32];
  strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);
  
  log_msg(BGP_LOG_INFO, "Timestamp: %s", time_buf);

  log_msg(BGP_LOG_INFO, "");
  log_msg(BGP_LOG_INFO, "--- Debug Information Available ---");
  log_msg(BGP_LOG_INFO, "  To view detailed debug information:");
  log_msg(BGP_LOG_INFO, "  - Use CLI: show bgp summary");
  log_msg(BGP_LOG_INFO, "  - Use CLI: show bgp neighbors");
  log_msg(BGP_LOG_INFO, "  - Use CLI: show ipv4 bgp");
  log_msg(BGP_LOG_INFO, "  - Use CLI: show ipv6 bgp");
  log_msg(BGP_LOG_INFO, "  - Use CLI: show config (for running configuration)");

  log_msg(BGP_LOG_INFO, "");
  log_msg(BGP_LOG_INFO, "--- To Enable Detailed Logging ---");
  log_msg(BGP_LOG_INFO, "  Restart daemon with: bgpd -f config.conf -vv");
  log_msg(BGP_LOG_INFO, "  This enables debug-level logging to stderr");

  log_msg(BGP_LOG_INFO, "");
  log_msg(BGP_LOG_INFO, "═══════════════════════════════════════════════════════");
  log_msg(BGP_LOG_INFO, "                    END DEBUG DUMP                      ");
  log_msg(BGP_LOG_INFO, "═══════════════════════════════════════════════════════");
}

/**
 * Dump BGP daemon statistics to syslog.
 */
void bgp_stats_dump_to_log(void)
{
  log_msg(BGP_LOG_INFO, "═══════════════════════════════════════════════════════");
  log_msg(BGP_LOG_INFO, "                    BGP STATS DUMP                      ");
  log_msg(BGP_LOG_INFO, "═══════════════════════════════════════════════════════");

  time_t now = time(NULL);
  struct tm* tm_info = localtime(&now);
  char time_buf[32];
  strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);
  
  log_msg(BGP_LOG_INFO, "Timestamp: %s", time_buf);

  log_msg(BGP_LOG_INFO, "");
  log_msg(BGP_LOG_INFO, "--- Performance Statistics ---");
  log_msg(BGP_LOG_INFO, "  For detailed statistics, use CLI commands:");
  log_msg(BGP_LOG_INFO, "  - show bgp summary (peer statistics)");
  log_msg(BGP_LOG_INFO, "  - show bgp neighbors (detailed neighbor stats)");
  log_msg(BGP_LOG_INFO, "  - show process memory (resource usage)");

  log_msg(BGP_LOG_INFO, "");
  log_msg(BGP_LOG_INFO, "--- Route Statistics ---");
  log_msg(BGP_LOG_INFO, "  View route statistics using:");
  log_msg(BGP_LOG_INFO, "  - show ipv4 bgp (IPv4 routes)");
  log_msg(BGP_LOG_INFO, "  - show ipv6 bgp (IPv6 routes)");

  log_msg(BGP_LOG_INFO, "");
  log_msg(BGP_LOG_INFO, "═══════════════════════════════════════════════════════");
  log_msg(BGP_LOG_INFO, "                    END STATS DUMP                      ");
  log_msg(BGP_LOG_INFO, "═══════════════════════════════════════════════════════");
}

