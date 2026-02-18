#pragma once

#include <stdio.h>

/**
 * Debug information dumping functions.
 * These are called by signal handlers (SIGUSR1/SIGUSR2) to dump
 * internal state for debugging and troubleshooting.
 */

/**
 * Dump BGP daemon debug information to syslog.
 * Called via SIGUSR1 signal handler.
 */
void bgp_debug_dump_to_log(void);

/**
 * Dump BGP daemon statistics to syslog.
 * Called via SIGUSR2 signal handler.
 */
void bgp_stats_dump_to_log(void);

