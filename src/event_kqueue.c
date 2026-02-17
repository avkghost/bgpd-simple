// src/event_kqueue.c
// Robust kqueue-based event loop for macOS.
// Fixes common EBADF/ENOENT issues, prevents UAF via stable udata tokens + generation,
// and tolerates late/stale events after EV_DELETE/close.
//
// Expected API (from include/bgp/event.h):
//   typedef struct event_loop event_loop_t;
//   event_loop_t* ev_create(void);
//   void ev_destroy(event_loop_t* l);
//   int  ev_add_fd(event_loop_t* l, int fd, uint32_t events,
//                  void (*cb)(int fd, uint32_t events, void* arg), void* arg);
//   int  ev_mod_fd(event_loop_t* l, int fd, uint32_t events,
//                  void (*cb)(int fd, uint32_t events, void* arg), void* arg);
//   int  ev_del_fd(event_loop_t* l, int fd);
//   int  ev_add_timer(event_loop_t* l, uint64_t ms, bool repeat,
//                     void (*cb)(void* arg), void* arg);
//   int  ev_del_timer(event_loop_t* l, int timer_id);
//   int  ev_run(event_loop_t* l);
//
// Event masks used by your code:
//   EV_READ  = 0x01u
//   EV_WRITE = 0x02u
//
// Design note: ev_fd_ent_t objects are allocated from a slab pool (FD_POOL_SLAB
// entries per slab, slabs linked via next pointer).  Addresses never move after
// allocation, so the &e->token pointer stored as kqueue udata remains valid for
// the lifetime of the loop — eliminating the UAF that a realloc'd flat array
// would cause.

#include "bgp/event.h"

#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <time.h>

#ifndef EV_READ
#define EV_READ  0x01u
#endif
#ifndef EV_WRITE
#define EV_WRITE 0x02u
#endif

// ---------- Time helpers ----------
static uint64_t now_ms(void){
  struct timespec ts;
#if defined(CLOCK_MONOTONIC)
  if(clock_gettime(CLOCK_MONOTONIC, &ts) == 0){
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
  }
#endif
  // Fallback
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return (uint64_t)tv.tv_sec * 1000ULL + (uint64_t)tv.tv_usec / 1000ULL;
}

// ---------- FD handling ----------
typedef void (*ev_fd_cb_t)(int fd, uint32_t events, void* arg);
typedef void (*ev_timer_cb_t)(void* arg);

typedef struct ev_fd_token {
  // Stable udata pointer handed to kevent; never freed until loop destroy.
  // Used to reject stale events from previous generations.
  uint64_t gen_snapshot;
  struct ev_fd_ent* ent;
} ev_fd_token_t;

typedef struct ev_fd_ent {
  int fd;
  uint32_t mask;
  ev_fd_cb_t cb;
  void* arg;

  bool alive;
  uint64_t gen;

  ev_fd_token_t token;

  struct ev_fd_ent* next; // intrusive list within slab / free list
} ev_fd_ent_t;

// Slab allocator for ev_fd_ent_t — keeps entry addresses stable across growth
// so that &e->token handed to kqueue as udata is never invalidated by realloc.
#define FD_POOL_SLAB 32

typedef struct ev_fd_slab {
  ev_fd_ent_t entries[FD_POOL_SLAB];
  struct ev_fd_slab* next;
} ev_fd_slab_t;

typedef struct ev_fd_pool {
  ev_fd_slab_t* slabs;     // linked list of allocated slabs
  ev_fd_ent_t*  freelist;  // singly-linked free entries (via ->next)
  ev_fd_ent_t*  live_head; // intrusive list of all live+dead entries for iteration
} ev_fd_pool_t;

// ---------- Timer handling ----------
typedef struct ev_timer {
  int id;
  bool alive;
  bool repeat;

  uint64_t interval_ms;
  uint64_t due_ms;

  ev_timer_cb_t cb;
  void* arg;
} ev_timer_t;

struct event_loop {
  int kq;
  bool running;

  // FD entries via stable-address slab pool (no realloc, so udata ptrs stay valid)
  ev_fd_pool_t fdpool;

  // Timers — plain growable array; timer entries are not stored as kqueue udata
  ev_timer_t* timers;
  size_t timers_len;
  size_t timers_cap;
  int next_timer_id;
};

// ---------- Internal utilities ----------
static void kq_log(const char* op, int fd){
  // Keep it lightweight; avoid crashing/asserting in allocator/stdio.
  fprintf(stderr, "[kqueue] %s fd=%d errno=%d (%s)\n", op, fd, errno, strerror(errno));
}

// ---------- Slab pool operations ----------

// Allocate a new slab and push all its entries onto the freelist.
static int fdpool_grow(ev_fd_pool_t* p){
  ev_fd_slab_t* slab = (ev_fd_slab_t*)calloc(1, sizeof(ev_fd_slab_t));
  if(!slab) return -1;

  slab->next = p->slabs;
  p->slabs = slab;

  // Push entries onto freelist in reverse so allocation order is forward.
  for(int i = FD_POOL_SLAB - 1; i >= 0; i--){
    slab->entries[i].next = p->freelist;
    p->freelist = &slab->entries[i];
  }
  return 0;
}

static ev_fd_ent_t* fdpool_alloc(ev_fd_pool_t* p){
  if(!p->freelist && fdpool_grow(p) < 0) return NULL;

  ev_fd_ent_t* e = p->freelist;
  p->freelist = e->next;

  memset(e, 0, sizeof(*e));
  e->fd = -1;

  // Prepend to live list.
  e->next = p->live_head;
  p->live_head = e;
  return e;
}

static void fdpool_free_all(ev_fd_pool_t* p){
  ev_fd_slab_t* s = p->slabs;
  while(s){
    ev_fd_slab_t* nx = s->next;
    free(s);
    s = nx;
  }
  p->slabs = NULL;
  p->freelist = NULL;
  p->live_head = NULL;
}

// ---------- FD lookup helpers ----------

static ev_fd_ent_t* fd_find(event_loop_t* l, int fd){
  if(!l || fd < 0) return NULL;
  for(ev_fd_ent_t* e = l->fdpool.live_head; e; e = e->next){
    if(e->fd == fd) return e;
  }
  return NULL;
}

static ev_fd_ent_t* fd_get_or_add(event_loop_t* l, int fd){
  ev_fd_ent_t* e = fd_find(l, fd);
  if(e) return e;

  e = fdpool_alloc(&l->fdpool);
  if(!e) return NULL;

  e->fd = fd;
  e->alive = false;
  e->gen = 1;
  // token.ent points back to this entry; address is stable for loop lifetime.
  e->token.ent = e;
  e->token.gen_snapshot = e->gen;
  return e;
}

static int kq_apply_one(event_loop_t* l, int fd, int filt, uint16_t flags, void* udata){
  struct kevent ch;
  EV_SET(&ch, (uintptr_t)fd, filt, flags, 0, 0, udata);

  if(kevent(l->kq, &ch, 1, NULL, 0, NULL) < 0){
    return -1;
  }
  return 0;
}

static int kq_set_mask(event_loop_t* l, ev_fd_ent_t* e, uint32_t newmask){
  if(!l || !e || e->fd < 0) return -1;

  // Use stable token pointer as udata; update snapshot to current generation.
  e->token.ent = e;
  e->token.gen_snapshot = e->gen;

  // READ
  if(newmask & EV_READ){
    if(kq_apply_one(l, e->fd, EVFILT_READ, EV_ADD | EV_ENABLE, &e->token) < 0){
      if(errno == EEXIST){
        // If already present, just enable.
        if(kq_apply_one(l, e->fd, EVFILT_READ, EV_ENABLE, &e->token) < 0){
          kq_log("EV_ENABLE(READ)", e->fd);
          return -1;
        }
      } else {
        kq_log("EV_ADD(READ)", e->fd);
        return -1;
      }
    }
  } else {
    // Delete read filter if it existed
    if(kq_apply_one(l, e->fd, EVFILT_READ, EV_DELETE, NULL) < 0){
      if(errno != EBADF && errno != ENOENT){
        kq_log("EV_DELETE(READ)", e->fd);
        return -1;
      }
    }
  }

  // WRITE
  if(newmask & EV_WRITE){
    if(kq_apply_one(l, e->fd, EVFILT_WRITE, EV_ADD | EV_ENABLE, &e->token) < 0){
      if(errno == EEXIST){
        if(kq_apply_one(l, e->fd, EVFILT_WRITE, EV_ENABLE, &e->token) < 0){
          kq_log("EV_ENABLE(WRITE)", e->fd);
          return -1;
        }
      } else {
        kq_log("EV_ADD(WRITE)", e->fd);
        return -1;
      }
    }
  } else {
    if(kq_apply_one(l, e->fd, EVFILT_WRITE, EV_DELETE, NULL) < 0){
      if(errno != EBADF && errno != ENOENT){
        kq_log("EV_DELETE(WRITE)", e->fd);
        return -1;
      }
    }
  }

  return 0;
}

// ---------- Public API ----------
event_loop_t* ev_create(void){
  event_loop_t* l = (event_loop_t*)calloc(1, sizeof(event_loop_t));
  if(!l) return NULL;

  l->kq = kqueue();
  if(l->kq < 0){
    free(l);
    return NULL;
  }

  l->running = false;
  // fdpool is zero-initialised by calloc; no further setup needed.

  l->timers = NULL;
  l->timers_len = 0;
  l->timers_cap = 0;
  l->next_timer_id = 1;

  return l;
}

void ev_destroy(event_loop_t* l){
  if(!l) return;

  // Best-effort: delete all fd filters (ignore EBADF/ENOENT)
  for(ev_fd_ent_t* e = l->fdpool.live_head; e; e = e->next){
    if(e->fd >= 0){
      (void)kq_apply_one(l, e->fd, EVFILT_READ,  EV_DELETE, NULL);
      (void)kq_apply_one(l, e->fd, EVFILT_WRITE, EV_DELETE, NULL);
    }
  }

  if(l->kq >= 0){
    close(l->kq);
    l->kq = -1;
  }

  fdpool_free_all(&l->fdpool);
  free(l->timers);
  free(l);
}

int ev_add_fd(event_loop_t* l, int fd, uint32_t events,
              void (*cb)(int fd, uint32_t events, void* arg), void* arg)
{
  if(!l || fd < 0 || !cb) return -1;

  ev_fd_ent_t* e = fd_get_or_add(l, fd);
  if(!e) return -1;

  // New registration generation
  e->gen++;
  if(e->gen == 0) e->gen = 1;

  e->alive = true;
  e->mask = events;
  e->cb = cb;
  e->arg = arg;

  if(kq_set_mask(l, e, events) < 0){
    e->alive = false;
    e->cb = NULL;
    e->arg = NULL;
    return -1;
  }
  return 0;
}

int ev_mod_fd(event_loop_t* l, int fd, uint32_t events,
              void (*cb)(int fd, uint32_t events, void* arg), void* arg)
{
  if(!l || fd < 0) return -1;

  ev_fd_ent_t* e = fd_find(l, fd);
  if(!e || !e->alive){
    // If not present, treat as add
    return ev_add_fd(l, fd, events, cb, arg);
  }

  // Update callback/arg if a new callback is provided (arg may legitimately be NULL)
  if(cb){
    e->cb  = cb;
    e->arg = arg;
  }

  e->mask = events;

  if(kq_set_mask(l, e, events) < 0){
    return -1;
  }
  return 0;
}

int ev_del_fd(event_loop_t* l, int fd){
  if(!l || fd < 0) return 0;

  ev_fd_ent_t* e = fd_find(l, fd);
  if(!e){
    // Nothing to delete.
    return 0;
  }

  // Mark dead first to ignore any late events
  e->alive = false;
  e->cb = NULL;
  e->arg = NULL;
  e->mask = 0;

  // Bump generation so stale queued events (with old snapshot) get ignored.
  e->gen++;
  if(e->gen == 0) e->gen = 1;

  // Best-effort delete (ignore EBADF/ENOENT)
  if(kq_apply_one(l, fd, EVFILT_READ, EV_DELETE, NULL) < 0){
    if(errno != EBADF && errno != ENOENT) kq_log("EV_DELETE(READ)", fd);
  }
  if(kq_apply_one(l, fd, EVFILT_WRITE, EV_DELETE, NULL) < 0){
    if(errno != EBADF && errno != ENOENT) kq_log("EV_DELETE(WRITE)", fd);
  }

  return 0;
}

// ---------- Timers ----------
static ev_timer_t* timer_find(event_loop_t* l, int id){
  if(!l || id <= 0) return NULL;
  for(size_t i = 0; i < l->timers_len; i++){
    if(l->timers[i].id == id) return &l->timers[i];
  }
  return NULL;
}

int ev_add_timer(event_loop_t* l, uint64_t ms, bool repeat,
                 void (*cb)(void* arg), void* arg)
{
  if(!l || !cb) return -1;
  if(ms == 0) ms = 1;

  if(l->timers_len == l->timers_cap){
    size_t ncap = (l->timers_cap == 0) ? 32 : l->timers_cap * 2;
    // Guard against overflow in the size calculation.
    if(ncap > (size_t)-1 / sizeof(ev_timer_t)) return -1;
    ev_timer_t* n = (ev_timer_t*)realloc(l->timers, ncap * sizeof(ev_timer_t));
    if(!n) return -1;
    l->timers = n;
    l->timers_cap = ncap;
  }

  int id = l->next_timer_id++;
  if(l->next_timer_id <= 0) l->next_timer_id = 1;

  ev_timer_t* t = &l->timers[l->timers_len++];
  memset(t, 0, sizeof(*t));
  t->id = id;
  t->alive = true;
  t->repeat = repeat;
  t->interval_ms = ms;
  t->due_ms = now_ms() + ms;
  t->cb = cb;
  t->arg = arg;

  return id;
}

int ev_del_timer(event_loop_t* l, int timer_id){
  if(!l || timer_id <= 0) return 0;
  ev_timer_t* t = timer_find(l, timer_id);
  if(!t) return 0;
  t->alive = false;
  t->cb = NULL;
  t->arg = NULL;
  return 0;
}

static uint64_t timers_next_due_in_ms(event_loop_t* l){
  uint64_t now = now_ms();
  uint64_t best = UINT64_MAX;

  for(size_t i = 0; i < l->timers_len; i++){
    ev_timer_t* t = &l->timers[i];
    if(!t->alive || !t->cb) continue;
    if(t->due_ms <= now) return 0;
    uint64_t d = t->due_ms - now;
    if(d < best) best = d;
  }

  if(best == UINT64_MAX) return UINT64_MAX;
  return best;
}

static void timers_fire_due(event_loop_t* l){
  uint64_t now = now_ms();
  // Snapshot len so newly-added timers (from callbacks) are not fired this pass.
  // Note: callbacks may realloc l->timers, so we must re-index via l->timers[i]
  // each iteration rather than keeping a pointer 't' across the callback.
  size_t snap_len = l->timers_len;
  for(size_t i = 0; i < snap_len; i++){
    // Re-read pointer each iteration: l->timers may have moved due to realloc
    // inside a callback that called ev_add_timer.
    ev_timer_t* t = &l->timers[i];
    if(!t->alive || !t->cb) continue;
    if(t->due_ms > now) continue;

    // Capture fields before callback; callback may ev_del_timer this entry.
    ev_timer_cb_t cb = t->cb;
    void* arg = t->arg;
    bool repeat = t->repeat;
    uint64_t interval = t->interval_ms;

    if(!repeat){
      t->alive = false;
      t->cb = NULL;
      t->arg = NULL;
    } else {
      // Avoid drift: schedule next from "now"
      t->due_ms = now + interval;
    }

    cb(arg);
    // After callback, t may be stale if l->timers was reallocated; do not use t.
  }

  // Optional compaction: remove dead timers occasionally
  // Keep it simple: compact if too many dead entries.
  size_t dead = 0;
  for(size_t i = 0; i < l->timers_len; i++){
    if(!l->timers[i].alive || !l->timers[i].cb) dead++;
  }
  if(dead > 32 && dead * 2 > l->timers_len){
    size_t w = 0;
    for(size_t i = 0; i < l->timers_len; i++){
      if(l->timers[i].alive && l->timers[i].cb){
        if(w != i) l->timers[w] = l->timers[i];
        w++;
      }
    }
    l->timers_len = w;
  }
}

// ---------- Run loop ----------
int ev_run(event_loop_t* l){
  if(!l) return -1;
  l->running = true;

  // Buffer for returned events
  struct kevent evs[64];

  while(l->running){
    // Fire timers that are already due before blocking
    timers_fire_due(l);

    uint64_t to_ms = timers_next_due_in_ms(l);

    struct timespec ts;
    struct timespec* tsp = NULL;
    if(to_ms == UINT64_MAX){
      tsp = NULL; // block indefinitely for fd events
    } else {
      ts.tv_sec = (time_t)(to_ms / 1000ULL);
      ts.tv_nsec = (long)((to_ms % 1000ULL) * 1000000ULL);
      tsp = &ts;
    }

    int n = kevent(l->kq, NULL, 0, evs, (int)(sizeof(evs)/sizeof(evs[0])), tsp);
    if(n < 0){
      if(errno == EINTR) continue;
      // This is the message you saw: kevent: Bad file descriptor
      // If kqueue itself is bad, we cannot recover.
      kq_log("kevent(wait)", -1);
      return -1;
    }

    // Timers may have expired while we waited.
    timers_fire_due(l);

    for(int i = 0; i < n; i++){
      struct kevent* kev = &evs[i];

      // Ignore timer-like filters; we don’t use EVFILT_TIMER here.
      if(kev->filter != EVFILT_READ && kev->filter != EVFILT_WRITE) continue;

      ev_fd_token_t* tok = (ev_fd_token_t*)kev->udata;
      if(!tok || !tok->ent) continue;

      ev_fd_ent_t* e = tok->ent;

      // Reject stale events from previous generations or deleted entries
      if(!e->alive) continue;
      if(tok->gen_snapshot != e->gen) continue;
      if(e->fd < 0) continue;
      if(!e->cb) continue;

      uint32_t mask = 0;
      if(kev->filter == EVFILT_READ)  mask |= EV_READ;
      if(kev->filter == EVFILT_WRITE) mask |= EV_WRITE;

      // EV_EOF indicates hangup; still report to callback so your FSM can tear down.
      // Many stacks use it to trigger "TCP_FAIL".
      // We keep mask as read/write; your recv() will return 0 or error.
      e->cb(e->fd, mask, e->arg);
    }
  }

  return 0;
}

// Optional helper if your code wants to stop the loop (not required by your current snippets)
void ev_stop(event_loop_t* l){
  if(l) l->running = false;
}
