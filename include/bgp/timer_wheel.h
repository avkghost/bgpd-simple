#pragma once
#include <stdint.h>
#include <stdbool.h>

#include "bgp/event.h"   // for ev_timer_cb

typedef struct timer_wheel timer_wheel_t;

timer_wheel_t* tw_create(uint64_t tick_ms, uint32_t slots);
void tw_destroy(timer_wheel_t* tw);

int tw_add(timer_wheel_t* tw,
           uint64_t now_ms,
           uint64_t delay_ms,
           bool periodic,
           ev_timer_cb cb,
           void* arg);

void tw_del(timer_wheel_t* tw, int id);

uint64_t tw_next_deadline_ms(timer_wheel_t* tw, uint64_t now_ms);
void tw_advance(timer_wheel_t* tw, uint64_t now_ms);
