#include "bgp/update.h"
#include <string.h>
#include <arpa/inet.h>

static int get_u16(const uint8_t* p){ return (p[0]<<8) | p[1]; }
static void put_u16(uint8_t* p, uint16_t v){ p[0]=(uint8_t)(v>>8); p[1]=(uint8_t)(v); }

void update4_init(bgp_update4_t* u){
  memset(u, 0, sizeof(*u));
  attrs_init(&u->attrs);
}

static int decode_prefixes(bgp_prefix4_t* arr, int max, int* count, const uint8_t* p, int len){
  int off=0;
  *count=0;
  while(off < len){
    if(*count >= max) return -1;
    uint8_t plen = p[off++];
    int bytes = (plen + 7)/8;
    if(off + bytes > len) return -1;
    struct in_addr a; a.s_addr = 0;
    uint8_t tmp[4]={0,0,0,0};
    memcpy(tmp, p+off, (size_t)bytes);
    memcpy(&a, tmp, 4);
    arr[*count].pfx = a;
    arr[*count].plen = plen;
    (*count)++;
    off += bytes;
  }
  return 0;
}

static int encode_prefixes(uint8_t* out, int outlen, const bgp_prefix4_t* arr, int count){
  int off=0;
  for(int i=0;i<count;i++){
    uint8_t plen = arr[i].plen;
    int bytes = (plen + 7)/8;
    if(off + 1 + bytes > outlen) return -1;
    out[off++] = plen;
    uint8_t tmp[4]={0,0,0,0};
    memcpy(tmp, &arr[i].pfx, 4);
    memcpy(out+off, tmp, (size_t)bytes);
    off += bytes;
  }
  return off;
}

int update4_decode(bgp_update4_t* u, const uint8_t* msg, int msglen, bool is_ebgp){
  // msg points to full BGP message (including 19-byte header)
  if(msglen < 19+4) return -1;
  const uint8_t* p = msg + 19;
  int len = msglen - 19;

  int off=0;
  if(off+2>len) return -1;
  int withdrawn_len = get_u16(p+off); off+=2;
  if(off+withdrawn_len>len) return -1;

  if(decode_prefixes(u->withdrawn, 256, &u->withdrawn_count, p+off, withdrawn_len) < 0) return -1;
  off += withdrawn_len;

  if(off+2>len) return -1;
  int attrs_len = get_u16(p+off); off+=2;
  if(off+attrs_len>len) return -1;

  if(attrs_decode(&u->attrs, p+off, attrs_len, is_ebgp) < 0) return -1;
  off += attrs_len;

  int nlri_len = len - off;
  if(decode_prefixes(u->nlri, 256, &u->nlri_count, p+off, nlri_len) < 0) return -1;

  return 0;
}

int update4_encode(uint8_t* out, int outlen, const bgp_update4_t* u, bool include_local_pref){
  // Encodes UPDATE payload only (not 19-byte header)
  // layout: withdrawn_len(2), withdrawn, attrs_len(2), attrs, nlri
  int off=0;
  if(outlen < 4) return -1;

  // withdrawn
  uint8_t tmp_w[2048];
  int wlen = encode_prefixes(tmp_w, (int)sizeof(tmp_w), u->withdrawn, u->withdrawn_count);
  if(wlen < 0) return -1;
  put_u16(out+off, (uint16_t)wlen); off += 2;
  if(off+wlen > outlen) return -1;
  memcpy(out+off, tmp_w, (size_t)wlen); off += wlen;

  // attrs
  uint8_t tmp_a[2048];
  int alen = attrs_encode(tmp_a, (int)sizeof(tmp_a), &u->attrs, include_local_pref, u->as4_capable);
  if(alen < 0) return -1;
  if(off+2+alen > outlen) return -1;
  put_u16(out+off, (uint16_t)alen); off += 2;
  memcpy(out+off, tmp_a, (size_t)alen); off += alen;

  // nlri
  uint8_t tmp_n[2048];
  int nlen = encode_prefixes(tmp_n, (int)sizeof(tmp_n), u->nlri, u->nlri_count);
  if(nlen < 0) return -1;
  if(off+nlen > outlen) return -1;
  memcpy(out+off, tmp_n, (size_t)nlen); off += nlen;

  return off;
}
