#include "bgp/update_wire.h"

static int get_u16(const uint8_t* p){ return (p[0]<<8)|p[1]; }

int update_wire_split(const uint8_t* msg, int msglen, update_wire_t* out){
  if(msglen < 19+4) return -1;
  const uint8_t* p = msg + 19;
  int len = msglen - 19;
  int off=0;

  if(off+2>len) return -1;
  out->withdrawn_len = get_u16(p+off); off+=2;
  if(off+out->withdrawn_len>len) return -1;
  out->withdrawn = p+off;
  off += out->withdrawn_len;

  if(off+2>len) return -1;
  out->attrs_len = get_u16(p+off); off+=2;
  if(off+out->attrs_len>len) return -1;
  out->attrs = p+off;
  off += out->attrs_len;

  out->nlri = p+off;
  out->nlri_len = len - off;
  return 0;
}
