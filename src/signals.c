/**
 * Signal handling for BGP daemon.
 * 
 * Implements a portable, event-loop friendly signal handling system that
 * allows safe signal delivery without risk of async-unsafe operations.
 * 
 * Signals are caught by a simple atomic handler and delivered to the main
 * event loop via a self-pipe or eventfd mechanism.
 */

#include "bgp/signals.h"
#include "bgp/log.h"
#include "bgp/event.h"
#include "bgp/debug.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <pthread.h>

/* Linux-specific signalfd */
#ifdef __linux__
#include <sys/signalfd.h>
#define HAVE_SIGNALFD 1
#else
#define HAVE_SIGNALFD 0
#endif

/* Maximum number of tracked signals */
#define MAX_SIGNALS 64

/* Volatile counter for signal delivery */
static volatile sig_atomic_t g_signal_pending[NSIG] = {0};

/* Global signal context (matches forward declaration in header) */
struct bgp_signal_ctx {
  event_loop_t* loop;
  int signal_fd;        /* signalfd file descriptor (Linux) or self-pipe read (BSD) */
  int signal_pipe_wr;   /* self-pipe write fd (BSD only) */

  /* Per-signal handlers and info */
  struct {
    bgp_signal_handler callback;
    void* arg;
    bgp_signal_info_t info;
  } handlers[NSIG];

  int initialized;
};

typedef struct bgp_signal_ctx bgp_signal_ctx_t;

static bgp_signal_ctx_t g_signal_ctx = {0};

/**
 * Async-safe signal handler (called by OS for each signal).
 * Minimizes async-unsafe operations - just sets a flag and writes to pipe.
 */
static void signal_handler_async(int signum)
{
  if (signum < 0 || signum >= NSIG) return;

  /* Mark signal as pending (atomic operation) */
  g_signal_pending[signum] = 1;

  /* On BSD: write to self-pipe to wake event loop */
#if !HAVE_SIGNALFD && 0  /* Disabled for now - use simpler polling */
  int fd = g_signal_ctx.signal_pipe_wr;
  if (fd >= 0) {
    char byte = 1;
    ssize_t ret = write(fd, &byte, 1);
    (void)ret; /* Avoid unused warning */
  }
#endif
}

/**
 * Signal FD/pipe readable event handler.
 * Called by event loop when signals are pending.
 * Used on Linux with signalfd; on BSD, signals are polled via timer.
 */
static __attribute__((unused)) void signal_fd_handler(int fd, uint32_t events, void* arg)
{
  (void)arg;
  (void)events;
  (void)fd;

  bgp_signal_ctx_t* ctx = &g_signal_ctx;

#if HAVE_SIGNALFD
  /* Linux: use signalfd for efficient signal delivery */
  struct signalfd_siginfo si[32];
  ssize_t nread;

  while ((nread = read(fd, si, sizeof(si))) > 0) {
    int num_sigs = nread / sizeof(si[0]);

    for (int i = 0; i < num_sigs; i++) {
      int signum = si[i].ssi_signo;

      if (signum < 0 || signum >= NSIG) continue;

      ctx->handlers[signum].info.signum = signum;
      ctx->handlers[signum].info.count++;

      /* Call user callback if registered */
      if (ctx->handlers[signum].callback) {
        log_msg(BGP_LOG_INFO, "signal: received %d (%s)",
                signum, strsignal(signum));
        ctx->handlers[signum].callback(signum, ctx->handlers[signum].arg);
      }
    }
  }

  if (nread < 0 && errno != EAGAIN) {
    log_msg(BGP_LOG_WARN, "signal_fd_handler: read error: %m");
  }
#else
  /* BSD: check pending signals (polled via timer or here) */
  for (int sig = 1; sig < NSIG; sig++) {
    if (g_signal_pending[sig]) {
      g_signal_pending[sig] = 0;

      ctx->handlers[sig].info.signum = sig;
      ctx->handlers[sig].info.count++;

      if (ctx->handlers[sig].callback) {
        log_msg(BGP_LOG_INFO, "signal: received %d (%s)",
                sig, strsignal(sig));
        ctx->handlers[sig].callback(sig, ctx->handlers[sig].arg);
      }
    }
  }
#endif
}

/**
 * Initialize signal handling.
 *
 * On Linux: Creates a signalfd to receive signals safely in the event loop context.
 * On BSD/macOS: Sets up async handlers and polls via timer or event mechanism.
 */
int bgp_signals_init(void* loop_ptr)
{
  if (!loop_ptr) return -1;

  bgp_signal_ctx_t* ctx = &g_signal_ctx;
  memset(ctx, 0, sizeof(*ctx));
  for (int i = 0; i < NSIG; i++) {
    g_signal_pending[i] = 0;
  }

  ctx->loop = (event_loop_t*)loop_ptr;
  ctx->signal_fd = -1;
  ctx->signal_pipe_wr = -1;

#if HAVE_SIGNALFD
  /* Linux: use signalfd */
  sigset_t set;
  sigemptyset(&set);

  /* Create signalfd that listens to all signals */
  ctx->signal_fd = signalfd(-1, &set, SFD_CLOEXEC | SFD_NONBLOCK);
  if (ctx->signal_fd < 0) {
    log_msg(BGP_LOG_ERROR, "signalfd() failed: %m");
    return -1;
  }

  /* Register signalfd with event loop */
  if (ev_add_fd(ctx->loop, ctx->signal_fd, EV_READ, signal_fd_handler, NULL) < 0) {
    log_msg(BGP_LOG_ERROR, "ev_add_fd(signalfd) failed");
    close(ctx->signal_fd);
    ctx->signal_fd = -1;
    return -1;
  }

  log_msg(BGP_LOG_INFO, "signal handling initialized (Linux signalfd=%d)", ctx->signal_fd);
#else
  /* BSD/macOS: set up polling via timer */
  log_msg(BGP_LOG_INFO, "signal handling initialized (BSD polling mode)");
#endif

  ctx->initialized = 1;
  return 0;
}

/**
 * Register a signal handler.
 * On Linux: Blocks the signal so it's delivered via signalfd.
 * On BSD: Sets up async signal handler.
 */
int bgp_signal_register(uint32_t signum, bgp_signal_handler callback, void* arg)
{
  if (signum >= NSIG) return -1;
  if (!callback) return -1;

  bgp_signal_ctx_t* ctx = &g_signal_ctx;
  if (!ctx->initialized) {
    log_msg(BGP_LOG_ERROR, "signal system not initialized");
    return -1;
  }

  /* Store callback */
  ctx->handlers[signum].callback = callback;
  ctx->handlers[signum].arg = arg;
  memset(&ctx->handlers[signum].info, 0, sizeof(ctx->handlers[signum].info));
  ctx->handlers[signum].info.signum = signum;

#if HAVE_SIGNALFD
  /* Linux: Block the signal so signalfd receives it */
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, signum);

  if (pthread_sigmask(SIG_BLOCK, &set, NULL) < 0) {
    log_msg(BGP_LOG_WARN, "pthread_sigmask(SIG_BLOCK, %d): %m", signum);
    /* Not fatal - continue anyway */
  }

  /* Update signalfd to include this signal */
  sigset_t all_signals;
  sigemptyset(&all_signals);
  for (int i = 1; i < NSIG; i++) {
    if (ctx->handlers[i].callback) {
      sigaddset(&all_signals, i);
    }
  }

  if (signalfd(ctx->signal_fd, &all_signals, SFD_CLOEXEC | SFD_NONBLOCK) < 0) {
    log_msg(BGP_LOG_WARN, "signalfd() update failed: %m");
    return -1;
  }
#else
  /* BSD: Install async signal handler */
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = signal_handler_async;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART;

  if (sigaction(signum, &sa, NULL) < 0) {
    log_msg(BGP_LOG_WARN, "sigaction(%d): %m", signum);
    return -1;
  }
#endif

  log_msg(BGP_LOG_INFO, "registered handler for signal %d (%s)",
          signum, strsignal(signum));
  return 0;
}

/**
 * Unregister a signal handler.
 */
int bgp_signal_unregister(uint32_t signum)
{
  if (signum >= NSIG) return -1;
  
  bgp_signal_ctx_t* ctx = &g_signal_ctx;
  if (!ctx->initialized) return -1;
  
  ctx->handlers[signum].callback = NULL;
  ctx->handlers[signum].arg = NULL;
  
  /* Unblock the signal */
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, signum);
  pthread_sigmask(SIG_UNBLOCK, &set, NULL);
  
  return 0;
}

/**
 * Get signal statistics.
 */
bgp_signal_info_t* bgp_signal_get_info(uint32_t signum)
{
  if (signum >= NSIG) return NULL;
  
  bgp_signal_ctx_t* ctx = &g_signal_ctx;
  if (!ctx->initialized) return NULL;
  
  if (!ctx->handlers[signum].callback) return NULL;
  
  return &ctx->handlers[signum].info;
}

/**
 * Cleanup signal handling.
 */
void bgp_signals_cleanup(void)
{
  bgp_signal_ctx_t* ctx = &g_signal_ctx;
  
  if (ctx->signal_fd >= 0) {
    /* Unregister from event loop */
    if (ctx->loop) {
      ev_del_fd(ctx->loop, ctx->signal_fd);
    }
    close(ctx->signal_fd);
    ctx->signal_fd = -1;
  }
  
  /* Unblock all signals */
  sigset_t all;
  sigfillset(&all);
  pthread_sigmask(SIG_UNBLOCK, &all, NULL);
  
  memset(ctx, 0, sizeof(*ctx));
}

/**
 * Standard signal handlers
 */

void bgp_on_sigterm(uint32_t signum, void* arg)
{
  (void)signum;
  
  event_loop_t* loop = (event_loop_t*)arg;
  log_msg(BGP_LOG_WARN, "SIGTERM received - initiating graceful shutdown");
  
  if (loop) {
    ev_stop(loop);
  }
}

void bgp_on_sighup(uint32_t signum, void* arg)
{
  (void)signum;

  log_msg(BGP_LOG_INFO, "SIGHUP received - config reload requested");

  /* Note: Full config reload would require:
   * 1. Re-reading the config file from disk
   * 2. Comparing with current running config
   * 3. Gracefully updating changed peers
   * 4. Restarting modified BGP sessions
   * 5. Applying new policies
   *
   * This is a future enhancement. For now, we log the request.
   */
  (void)arg;  /* Future: use bgp_global_t* g = (bgp_global_t*)arg; */
  log_msg(BGP_LOG_WARN, "Config reload: restart daemon to apply changes");
}

void bgp_on_sigusr1(uint32_t signum, void* arg)
{
  (void)signum;
  (void)arg;

  log_msg(BGP_LOG_INFO, "SIGUSR1 received - debug dump requested");
  bgp_debug_dump_to_log();
}

void bgp_on_sigusr2(uint32_t signum, void* arg)
{
  (void)signum;
  (void)arg;

  log_msg(BGP_LOG_INFO, "SIGUSR2 received - stats dump requested");
  bgp_stats_dump_to_log();
}

