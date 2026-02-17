#pragma once
#include <stdint.h>
#include <stdbool.h>

#define EV_READ  0x0001u
#define EV_WRITE 0x0002u
#define EV_ERR   0x0004u
#define EV_HUP   0x0008u

typedef struct event_loop event_loop_t;

typedef void (*ev_io_cb)(int fd, uint32_t events, void* arg);
typedef void (*ev_timer_cb)(void* arg);

event_loop_t* ev_create(void);
void ev_destroy(event_loop_t* l);

int  ev_add_fd(event_loop_t* l, int fd, uint32_t events, ev_io_cb cb, void* arg);
int  ev_mod_fd(event_loop_t* l, int fd, uint32_t events, ev_io_cb cb, void* arg);
int  ev_del_fd(event_loop_t* l, int fd);

int  ev_add_timer(event_loop_t* l, uint64_t ms, bool periodic, ev_timer_cb cb, void* arg);
int  ev_del_timer(event_loop_t* l, int timer_id);

int  ev_run(event_loop_t* l);
void ev_stop(event_loop_t* l);
uint64_t ev_now_ms(void);
