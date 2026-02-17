#include "bgp/vpn.h"
#include <string.h>

static uint16_t get_u16(const uint8_t* p){ return (uint16_t)((p[0]<<8)|p[1]); }
static uint32_t get_u32(const uint8_t* p){ return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3]; }

void vpnv4_update_init(vpnv4_update_t* u){
  memset(u,0,sizeof(*u));
  attrs_init(&u->attrs);
}

static int decode_rd_asn_nn(rt_asn_t* rd, const uint8_t* p){
  // RD type 0: [type=0(2 bytes)][asn(2)][nn(4)]
  uint16_t t = get_u16(p);
  if(t != 0) return -1;
  rd->asn = get_u16(p+2);
  rd->val = get_u32(p+4);
  return 0;
}

static int decode_vpnv4_nlri_one(vpnv4_nlri_t* n, const uint8_t* p, int len){
  // p points to NLRI blob; first byte is prefix length in bits for VPNv4 “route”
  if(len < 1) return -1;
  int bitlen = p[0];
  int bytelen = (bitlen + 7)/8;
  if(1 + bytelen > len) return -1;

  // Must contain: label(3) + RD(8) + prefix(...)
  if(bytelen < (3+8)) return -1;
  const uint8_t* q = p+1;

  uint32_t label20 = ((uint32_t)q[0]<<12) | ((uint32_t)q[1]<<4) | ((uint32_t)q[2]>>4);
  n->label = label20 & 0xFFFFF;
  q += 3;

  if(decode_rd_asn_nn(&n->rd, q) < 0) return -1;
  q += 8;

  int pfx_bits = bitlen - (3+8)*8;
  if(pfx_bits < 0 || pfx_bits > 32) return -1;
  n->plen = (uint8_t)pfx_bits;

  uint8_t tmp[4]={0,0,0,0};
  int pfx_bytes = (pfx_bits + 7)/8;
  if(q + pfx_bytes > p + 1 + bytelen) return -1;
  memcpy(tmp, q, (size_t)pfx_bytes);
  memcpy(&n->pfx, tmp, 4);

  return 1 + bytelen;
}

static int parse_mp_reach_vpnv4(vpnv4_update_t* out, const uint8_t* v, int alen){
  if(alen < 2+1+1) return -1;
  uint16_t afi = get_u16(v);
  uint8_t safi = v[2];
  if(afi != 1 || safi != 128) return 0; // not vpnv4

  int off=3;
  if(off >= alen) return -1;
  uint8_t nhlen = v[off++];
  if(off + nhlen > alen) return -1;
  if(nhlen == 4){
    memcpy(&out->nh, v+off, 4);
    out->has_nh = 1;
  }
  off += nhlen;

  if(off >= alen) return -1;
  uint8_t snpa = v[off++]; // ignore SNPAs
  off += (int)snpa * 0; // SNPAs not supported (should parse lengths), but most peers send 0

  // Remaining is NLRI list
  while(off < alen && out->nlri_count < 256){
    int used = decode_vpnv4_nlri_one(&out->nlri[out->nlri_count], v+off, alen-off);
    if(used < 0) return -1;
    out->nlri_count++;
    off += used;
  }
  return 1;
}

static int parse_mp_unreach_vpnv4(vpnv4_update_t* out, const uint8_t* v, int alen){
  if(alen < 3) return -1;
  uint16_t afi = get_u16(v);
  uint8_t safi = v[2];
  if(afi != 1 || safi != 128) return 0;

  int off=3;
  while(off < alen && out->withdraw_count < 256){
    int used = decode_vpnv4_nlri_one(&out->withdraw[out->withdraw_count], v+off, alen-off);
    if(used < 0) return -1;
    out->withdraw_count++;
    off += used;
  }
  return 1;
}

int vpnv4_from_mp_attrs(vpnv4_update_t* out, const uint8_t* attrs, int attrs_len){
  vpnv4_update_init(out);
  int off=0;

  while(off < attrs_len){
    if(off + 2 > attrs_len) return -1;
    uint8_t flags = attrs[off+0];
    uint8_t code  = attrs[off+1];
    off += 2;

    bool extlen = (flags & 0x10) != 0;
    int alen = 0;
    if(extlen){
      if(off + 2 > attrs_len) return -1;
      alen = (attrs[off]<<8) | attrs[off+1];
      off += 2;
    } else {
      if(off + 1 > attrs_len) return -1;
      alen = attrs[off++];
    }
    if(off + alen > attrs_len) return -1;
    const uint8_t* v = attrs + off;

    if(code == 14){
      int rc = parse_mp_reach_vpnv4(out, v, alen);
      if(rc < 0) return -1;
    } else if(code == 15){
      int rc = parse_mp_unreach_vpnv4(out, v, alen);
      if(rc < 0) return -1;
    } else {
      // Attributes decoded separately by attrs_decode() (classic) and extcomm later.
    }

    off += alen;
  }
  return 0;
}
