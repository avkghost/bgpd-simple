/*
 * Platform-neutral event loop interface.
 *
 * Provides portable abstraction over epoll (Linux) and kqueue (BSD/macOS).
 * Single API, different implementations selected at build time.
 */

#ifndef BGP_PLATFORM_EVENT_H
#define BGP_PLATFORM_EVENT_H

#include <stdint.h>
#include <stdbool.h>

/* Opaque handle to event loop — implementation-specific */
typedef struct event_loop event_loop_t;

/* Event type flags */
#define EVENT_READ   0x01
#define EVENT_WRITE  0x02

/* I/O event callback signature */
typedef void (*event_io_cb)(int fd, uint32_t events, void* arg);

/* Timer event callback signature */
typedef void (*event_timer_cb)(void* arg);

/* Create a new event loop */
event_loop_t* event_loop_create(void);

/* Destroy event loop and free resources */
void event_loop_destroy(event_loop_t* loop);

/* Register file descriptor for I/O events (read/write) */
int event_add_fd(event_loop_t* loop, int fd, uint32_t events,
                 event_io_cb cb, void* arg);

/* Modify events on existing file descriptor */
int event_mod_fd(event_loop_t* loop, int fd, uint32_t events);

/* Unregister and stop monitoring file descriptor */
int event_del_fd(event_loop_t* loop, int fd);

/* Register a timer (periodic or one-shot) */
int event_add_timer(event_loop_t* loop, uint64_t ms_delay, bool periodic,
                    event_timer_cb cb, void* arg);

/* Unregister a timer */
int event_del_timer(event_loop_t* loop, int timer_id);

/* Run the event loop (blocking) — returns when event_stop is called */
int event_run(event_loop_t* loop);

/* Stop the event loop (async-safe) */
void event_stop(event_loop_t* loop);

/* Get current time in milliseconds (monotonic) */
uint64_t event_now_ms(void);

#endif /* BGP_PLATFORM_EVENT_H */
