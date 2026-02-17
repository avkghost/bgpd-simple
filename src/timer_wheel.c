// src/timer_wheel.c
// Simple timer wheel used by event_epoll.c
// - millisecond resolution
// - one-shot and periodic timers
// - integrates with event loop via ev_now_ms() and ev_timer_cb signature in bgp/event.h
//
// This file assumes the following (typical) declarations exist in include/bgp/event.h:
//   typedef void (*ev_timer_cb)(void* arg);
//   typedef struct timer_wheel timer_wheel_t;
//   timer_wheel_t* tw_create(uint64_t tick_ms, uint32_t slots);
//   void tw_destroy(timer_wheel_t* tw);
//   int tw_add(timer_wheel_t* tw, uint64_t now_ms, uint64_t delay_ms, bool periodic, ev_timer_cb cb, void* arg);
//   void tw_del(timer_wheel_t* tw, int id);
//   uint64_t tw_next_deadline_ms(timer_wheel_t* tw, uint64_t now_ms);
//   void tw_advance(timer_wheel_t* tw, uint64_t now_ms);
//
// If your header differs, paste include/bgp/event.h and I’ll align the exact symbols.

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "bgp/timer_wheel.h"

typedef struct tw_timer {
  int id;
  bool in_use;
  bool periodic;

  uint64_t period_ms;     // if periodic
  uint64_t expire_ms;     // absolute ms

  ev_timer_cb cb;
  void* arg;

  // intrusive doubly-linked list in a slot
  struct tw_timer* prev;
  struct tw_timer* next;
} tw_timer_t;

struct timer_wheel {
  uint64_t tick_ms;
  uint32_t slots;

  uint64_t base_ms;       // wheel base time (aligned to tick)
  uint32_t cursor;        // current slot index

  int next_id;

  // slots are lists of timers
  tw_timer_t** heads;

  // id -> timer (simple array map); id starts at 1
  tw_timer_t** id_map;
  uint32_t id_map_cap;
};

static uint64_t align_down(uint64_t v, uint64_t a){
  return (a == 0) ? v : (v / a) * a;
}

static void list_push(tw_timer_t** head, tw_timer_t* t){
  t->prev = NULL;
  t->next = *head;
  if(*head) (*head)->prev = t;
  *head = t;
}

static void list_remove(tw_timer_t** head, tw_timer_t* t){
  if(t->prev) t->prev->next = t->next;
  if(t->next) t->next->prev = t->prev;
  if(*head == t) *head = t->next;
  t->prev = t->next = NULL;
}

static int ensure_id_map(timer_wheel_t* tw, int id){
  if(id <= 0) return -1;
  if((uint32_t)id < tw->id_map_cap) return 0;

  uint32_t newcap = tw->id_map_cap ? tw->id_map_cap : 128;
  while(newcap <= (uint32_t)id) newcap *= 2;

  tw_timer_t** n = (tw_timer_t**)realloc(tw->id_map, newcap * sizeof(tw_timer_t*));
  if(!n) return -1;
  memset(n + tw->id_map_cap, 0, (newcap - tw->id_map_cap) * sizeof(tw_timer_t*));
  tw->id_map = n;
  tw->id_map_cap = newcap;
  return 0;
}

timer_wheel_t* tw_create(uint64_t tick_ms, uint32_t slots){
  if(tick_ms == 0 || slots < 8){
    errno = EINVAL;
    return NULL;
  }

  timer_wheel_t* tw = (timer_wheel_t*)calloc(1, sizeof(*tw));
  if(!tw) return NULL;

  tw->tick_ms = tick_ms;
  tw->slots = slots;
  tw->cursor = 0;
  tw->next_id = 1;

  tw->heads = (tw_timer_t**)calloc(slots, sizeof(tw_timer_t*));
  if(!tw->heads){
    free(tw);
    return NULL;
  }

  // base_ms will be initialized on first add/advance by caller-provided now_ms.
  tw->base_ms = 0;

  return tw;
}

void tw_destroy(timer_wheel_t* tw){
  if(!tw) return;

  // free all timers in all slots
  for(uint32_t i=0;i<tw->slots;i++){
    tw_timer_t* t = tw->heads[i];
    while(t){
      tw_timer_t* n = t->next;
      free(t);
      t = n;
    }
  }
  free(tw->heads);
  free(tw->id_map);
  free(tw);
}

static uint32_t slot_for(timer_wheel_t* tw, uint64_t expire_ms){
  // if base_ms not set yet, treat cursor at 0 and base aligned to expire - delay
  if(tw->base_ms == 0) tw->base_ms = align_down(expire_ms, tw->tick_ms);

  uint64_t delta = (expire_ms > tw->base_ms) ? (expire_ms - tw->base_ms) : 0;
  uint64_t ticks = delta / tw->tick_ms;
  return (uint32_t)((tw->cursor + (uint32_t)(ticks % tw->slots)) % tw->slots);
}

int tw_add(timer_wheel_t* tw,
           uint64_t now_ms,
           uint64_t delay_ms,
           bool periodic,
           ev_timer_cb cb,
           void* arg)
{
  if(!tw || !cb){
    errno = EINVAL;
    return -1;
  }

  if(tw->base_ms == 0){
    tw->base_ms = align_down(now_ms, tw->tick_ms);
    tw->cursor = 0;
  }

  uint64_t d = delay_ms;
  if(d < tw->tick_ms) d = tw->tick_ms; // minimum 1 tick so it will fire in the future

  int id = tw->next_id++;
  if(ensure_id_map(tw, id) < 0) return -1;

  tw_timer_t* t = (tw_timer_t*)calloc(1, sizeof(*t));
  if(!t) return -1;

  t->id = id;
  t->in_use = true;
  t->periodic = periodic;
  t->period_ms = periodic ? (delay_ms ? delay_ms : tw->tick_ms) : 0;
  t->expire_ms = now_ms + d;
  t->cb = cb;
  t->arg = arg;

  uint32_t s = slot_for(tw, t->expire_ms);
  list_push(&tw->heads[s], t);

  tw->id_map[id] = t;
  return id;
}

void tw_del(timer_wheel_t* tw, int id){
  if(!tw || id <= 0) return;
  if((uint32_t)id >= tw->id_map_cap) return;

  tw_timer_t* t = tw->id_map[id];
  if(!t) return;

  // find its slot by recompute; safe because expire_ms/base_ms defines it
  uint32_t s = slot_for(tw, t->expire_ms);
  list_remove(&tw->heads[s], t);
  tw->id_map[id] = NULL;
  free(t);
}

uint64_t tw_next_deadline_ms(timer_wheel_t* tw, uint64_t now_ms){
  if(!tw) return 0;
  if(tw->base_ms == 0){
    // no timers yet
    return 0;
  }

  // Scan up to one full revolution for earliest timer >= now
  uint64_t best = 0;

  for(uint32_t i=0;i<tw->slots;i++){
    uint32_t idx = (tw->cursor + i) % tw->slots;
    for(tw_timer_t* t = tw->heads[idx]; t; t = t->next){
      if(best == 0 || t->expire_ms < best) best = t->expire_ms;
    }
  }

  (void)now_ms;
  return best;
}

static void reschedule(timer_wheel_t* tw, tw_timer_t* t, uint64_t now_ms){
  // remove from old slot and reinsert
  uint32_t olds = slot_for(tw, t->expire_ms);
  list_remove(&tw->heads[olds], t);

  uint64_t p = t->period_ms ? t->period_ms : tw->tick_ms;
  uint64_t next = now_ms + p;
  t->expire_ms = next;

  uint32_t news = slot_for(tw, t->expire_ms);
  list_push(&tw->heads[news], t);
}

void tw_advance(timer_wheel_t* tw, uint64_t now_ms){
  if(!tw) return;

  if(tw->base_ms == 0){
    // nothing scheduled yet
    tw->base_ms = align_down(now_ms, tw->tick_ms);
    tw->cursor = 0;
    return;
  }

  // Advance wheel cursor tick-by-tick until base catches up with now
  uint64_t target_base = align_down(now_ms, tw->tick_ms);

  while(tw->base_ms < target_base){
    // move to next tick
    tw->base_ms += tw->tick_ms;
    tw->cursor = (tw->cursor + 1) % tw->slots;

    // process timers in current slot that are due
    tw_timer_t* t = tw->heads[tw->cursor];
    while(t){
      tw_timer_t* next = t->next;

      if(t->expire_ms <= now_ms){
        // fire
        if(!t->periodic){
          // delete
          list_remove(&tw->heads[tw->cursor], t);
          tw->id_map[t->id] = NULL;
          ev_timer_cb cb = t->cb;
          void* arg = t->arg;
          free(t);
          cb(arg);
        } else {
          // periodic: call then reschedule
          ev_timer_cb cb = t->cb;
          void* arg = t->arg;
          cb(arg);
          // t may have been deleted by callback (user called tw_del).
          // So check id_map still points to same timer.
          if((uint32_t)t->id < tw->id_map_cap && tw->id_map[t->id] == t){
            reschedule(tw, t, now_ms);
          }
        }
      }
      t = next;
    }
  }
}
