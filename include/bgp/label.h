#pragma once
#include <stdint.h>

#define LABEL_FREE_LIST_MAX 256

typedef struct {
  uint32_t next;
  uint32_t start;
  uint32_t end;

  /* recycled labels waiting for re-use */
  uint32_t freelist[LABEL_FREE_LIST_MAX];
  int      freelist_count;
} label_mgr_t;

void     label_mgr_init(label_mgr_t* m, uint32_t start, uint32_t end);
uint32_t label_alloc(label_mgr_t* m);
void     label_free(label_mgr_t* m, uint32_t label);
