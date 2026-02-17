#include "bgp/label.h"
#include <string.h>

void label_mgr_init(label_mgr_t* m, uint32_t start, uint32_t end){
  memset(m, 0, sizeof(*m));
  m->start = start;
  m->end   = end;
  m->next  = start;
}

uint32_t label_alloc(label_mgr_t* m){
  /* prefer recycled labels to keep the sequential pool intact */
  if(m->freelist_count > 0){
    return m->freelist[--m->freelist_count];
  }
  if(m->next > m->end) return 0; /* pool exhausted */
  return m->next++;
}

void label_free(label_mgr_t* m, uint32_t label){
  if(!label) return; /* 0 is sentinel "no label" */
  if(label < m->start || label > m->end) return; /* out of managed range */
  if(m->freelist_count >= LABEL_FREE_LIST_MAX) return; /* drop if full */
  m->freelist[m->freelist_count++] = label;
}
