#include "bgp/timer_wheel.h"
#include "bgp/event.h"
#include "bgp/log.h"
#include <stdlib.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <time.h>
#include <errno.h>
#include <string.h>

#define MAX_EVENTS 128

typedef struct fd_item {
  int fd;
  ev_io_cb cb;
  void* arg;
} fd_item_t;

typedef struct timer_item {
  int id;
  uint64_t due_ms;
  uint64_t period_ms;
  bool periodic;
  ev_timer_cb cb;
  void* arg;
  struct timer_item* next;
} timer_item_t;

struct event_loop {
  int ep;
  int stop;
  fd_item_t* fds;     // sparse array indexed by fd (simple for demo)
  int fds_cap;
  timer_item_t* timers;
  int next_timer_id;
};

uint64_t ev_now_ms(void){
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec*1000ULL + (uint64_t)ts.tv_nsec/1000000ULL;
}

static void ensure_fd_cap(event_loop_t* l, int fd){
  if (fd < l->fds_cap) return;
  int newcap = l->fds_cap ? l->fds_cap : 256;
  while (newcap <= fd) newcap *= 2;
  l->fds = (fd_item_t*)realloc(l->fds, (size_t)newcap * sizeof(fd_item_t));
  for(int i=l->fds_cap;i<newcap;i++){ l->fds[i].fd = -1; l->fds[i].cb=NULL; l->fds[i].arg=NULL; }
  l->fds_cap = newcap;
}

event_loop_t* ev_create(void){
  event_loop_t* l = calloc(1, sizeof(*l));
  l->ep = epoll_create1(EPOLL_CLOEXEC);
  if (l->ep < 0){ free(l); return NULL; }
  l->next_timer_id = 1;
  l->fds_cap = 0;
  l->fds = NULL;
  l->timers = NULL;
  return l;
}

void ev_destroy(event_loop_t* l){
  if(!l) return;
  if(l->ep>=0) close(l->ep);
  free(l->fds);
  while(l->timers){ timer_item_t* n=l->timers->next; free(l->timers); l->timers=n; }
  free(l);
}

int ev_add_fd(event_loop_t* l, int fd, uint32_t events, ev_io_cb cb, void* arg){
  ensure_fd_cap(l, fd);
  struct epoll_event ev = {0};

//  ev.events = events;
  uint32_t e = 0;
  if(events & EV_READ)  e |= EPOLLIN;
  if(events & EV_WRITE) e |= EPOLLOUT;
  if(events & EV_ERR)   e |= EPOLLERR;
  if(events & EV_HUP)   e |= EPOLLHUP;
  ev.events = e;

  ev.data.fd = fd;
  if (epoll_ctl(l->ep, EPOLL_CTL_ADD, fd, &ev) < 0) return -1;
  l->fds[fd].fd = fd;
  l->fds[fd].cb = cb;
  l->fds[fd].arg = arg;
  return 0;
}

int ev_mod_fd(event_loop_t* l, int fd, uint32_t events, ev_io_cb cb, void* arg){
  ensure_fd_cap(l, fd);
  struct epoll_event ev = {0};

  uint32_t e = 0;
  if(events & EV_READ)  e |= EPOLLIN;
  if(events & EV_WRITE) e |= EPOLLOUT;
  if(events & EV_ERR)   e |= EPOLLERR;
  if(events & EV_HUP)   e |= EPOLLHUP;
  ev.events = e;

  ev.data.fd = fd;
  if (epoll_ctl(l->ep, EPOLL_CTL_MOD, fd, &ev) < 0) return -1;

  l->fds[fd].fd = fd;
  l->fds[fd].cb = cb;
  l->fds[fd].arg = arg;
  return 0;
}

int ev_del_fd(event_loop_t* l, int fd){
  epoll_ctl(l->ep, EPOLL_CTL_DEL, fd, NULL);
  if (fd < l->fds_cap){
    l->fds[fd].fd = -1; l->fds[fd].cb=NULL; l->fds[fd].arg=NULL;
  }
  return 0;
}

static void timers_insert(event_loop_t* l, timer_item_t* t){
  if(!l->timers || t->due_ms < l->timers->due_ms){
    t->next = l->timers;
    l->timers = t;
    return;
  }
  timer_item_t* cur = l->timers;
  while(cur->next && cur->next->due_ms <= t->due_ms) cur = cur->next;
  t->next = cur->next;
  cur->next = t;
}

int ev_add_timer(event_loop_t* l, uint64_t ms, bool periodic, ev_timer_cb cb, void* arg){
  timer_item_t* t = calloc(1, sizeof(*t));
  t->id = l->next_timer_id++;
  t->due_ms = ev_now_ms() + ms;
  t->period_ms = ms;
  t->periodic = periodic;
  t->cb = cb;
  t->arg = arg;
  timers_insert(l, t);
  return t->id;
}

int ev_del_timer(event_loop_t* l, int timer_id){
  timer_item_t** pp = &l->timers;
  while(*pp){
    if((*pp)->id == timer_id){
      timer_item_t* dead=*pp;
      *pp = dead->next;
      free(dead);
      return 0;
    }
    pp = &(*pp)->next;
  }
  return -1;
}

int ev_run(event_loop_t* l){
  struct epoll_event evs[MAX_EVENTS];
  l->stop = 0;

  while(!l->stop){
    uint64_t now = ev_now_ms();
    int timeout_ms = -1;

    if(l->timers){
      if(l->timers->due_ms <= now) timeout_ms = 0;
      else {
        uint64_t diff = l->timers->due_ms - now;
        timeout_ms = (diff > (uint64_t)INT32_MAX) ? INT32_MAX : (int)diff;
      }
    }

    int n = epoll_wait(l->ep, evs, MAX_EVENTS, timeout_ms);
    if(n < 0){
      if(errno == EINTR) continue;
      log_msg(BGP_LOG_ERROR, "epoll_wait: %s", strerror(errno));
      return -1;
    }

    for(int i=0;i<n;i++){
      int fd = evs[i].data.fd;
      if(fd >= 0 && fd < l->fds_cap && l->fds[fd].cb){
//        l->fds[fd].cb(fd, evs[i].events, l->fds[fd].arg);
        uint32_t fired = 0;
        if(evs[i].events & EPOLLIN)  fired |= EV_READ;
        if(evs[i].events & EPOLLOUT) fired |= EV_WRITE;
        if(evs[i].events & EPOLLERR) fired |= EV_ERR;
        if(evs[i].events & EPOLLHUP) fired |= EV_HUP;
        l->fds[fd].cb(fd, fired, l->fds[fd].arg);
      }
    }

    now = ev_now_ms();
    while(l->timers && l->timers->due_ms <= now){
      timer_item_t* t = l->timers;
      l->timers = t->next;
      if(t->cb) t->cb(t->arg);
      if(t->periodic){
        t->due_ms = now + t->period_ms;
        t->next = NULL;
        timers_insert(l, t);
      } else {
        free(t);
      }
      now = ev_now_ms();
    }
  }
  return 0;
}

void ev_stop(event_loop_t* l){ l->stop = 1; }
