#include "bgp/extcomm.h"

bool rt_equal(rt_asn_t a, rt_asn_t b){ return a.asn==b.asn && a.val==b.val; }

bool rt_set_has(const extcomm_set_t* s, rt_asn_t rt){
  for(int i=0;i<s->rt_count;i++) if(rt_equal(s->rts[i], rt)) return true;
  return false;
}

bool rt_sets_intersect(const extcomm_set_t* a, const rt_asn_t* b, int bcnt){
  for(int i=0;i<a->rt_count;i++){
    for(int j=0;j<bcnt;j++){
      if(rt_equal(a->rts[i], b[j])) return true;
    }
  }
  return false;
}
