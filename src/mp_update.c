// src/mp_update.c
#include "bgp/mp_update.h"
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#define PA_FLAG_OPT       0x80
#define PA_FLAG_TRANS     0x40
#define PA_FLAG_PARTIAL   0x20
#define PA_FLAG_EXTLEN    0x10

#define PA_ORIGIN         1
#define PA_AS_PATH        2
#define PA_LOCAL_PREF     5

#define PA_MP_REACH       14
#define PA_MP_UNREACH     15

static uint8_t* put_u16(uint8_t* p, uint16_t v){ *p++=(uint8_t)(v>>8); *p++=(uint8_t)v; return p; }
static uint8_t* put_u32(uint8_t* p, uint32_t v){
  *p++=(uint8_t)(v>>24); *p++=(uint8_t)(v>>16); *p++=(uint8_t)(v>>8); *p++=(uint8_t)v;
  return p;
}

static int put_attr_hdr(uint8_t* p, int rem,
                        uint8_t flags, uint8_t code,
                        uint16_t len, int* hdr_len)
{
  if(!p || !hdr_len) return -1;
  if(len > 255) flags |= PA_FLAG_EXTLEN;

  if(flags & PA_FLAG_EXTLEN){
    if(rem < 4) return -1;
    p[0]=flags; p[1]=code; p[2]=(uint8_t)(len>>8); p[3]=(uint8_t)len;
    *hdr_len = 4;
    return 0;
  } else {
    if(rem < 3) return -1;
    p[0]=flags; p[1]=code; p[2]=(uint8_t)len;
    *hdr_len = 3;
    return 0;
  }
}

static int encode_origin(uint8_t* out, int outlen, uint8_t origin){
  int hlen = 0;
  // ORIGIN is well-known mandatory => Optional=0, Transitive=1 => 0x40
  if(put_attr_hdr(out, outlen, PA_FLAG_TRANS, PA_ORIGIN, 1, &hlen) < 0) return -1;
  if(outlen < hlen + 1) return -1;
  out[hlen] = origin; // 0=IGP, 1=EGP, 2=INCOMPLETE
  return hlen + 1;
}

static int encode_as_path(uint8_t* out, int outlen, bool is_ebgp, uint32_t local_asn){
  int hlen = 0;

  // iBGP: empty AS_PATH is valid (len=0)
  if(!is_ebgp){
    if(put_attr_hdr(out, outlen, PA_FLAG_TRANS, PA_AS_PATH, 0, &hlen) < 0) return -1;
    return hlen;
  }

  // eBGP: minimal AS_PATH = AS_SEQUENCE with one 2-byte ASN
  uint16_t asn16 = (local_asn > 65535) ? 23456 : (uint16_t)local_asn;

  if(put_attr_hdr(out, outlen, PA_FLAG_TRANS, PA_AS_PATH, 4, &hlen) < 0) return -1;
  if(outlen < hlen + 4) return -1;

  uint8_t* p = out + hlen;
  *p++ = 2; // AS_SEQUENCE
  *p++ = 1; // one ASN
  *p++ = (uint8_t)(asn16 >> 8);
  *p++ = (uint8_t)(asn16);
  return (int)(p - out);
}

static int encode_local_pref(uint8_t* out, int outlen, uint32_t lp){
  int hlen = 0;
  // LOCAL_PREF is well-known discretionary => Optional=0, Transitive=1 (0x40)
  if(put_attr_hdr(out, outlen, PA_FLAG_TRANS, PA_LOCAL_PREF, 4, &hlen) < 0) return -1;
  if(outlen < hlen + 4) return -1;
  uint8_t* p = out + hlen;
  p = put_u32(p, lp);
  return (int)(p - out);
}

static int encode_mp_reach(uint8_t* out, int outlen, const mp_reach_t* r){
  if(!r) return 0;
  if(!r->nlri && r->nlri_len) return -1;
  if(r->nh_len == 0) return -1;
  if((int)r->nh_len > (int)sizeof(r->nh)) return -1;

  // Value: AFI(2) + SAFI(1) + NHLen(1) + NH + SNPALen(1) + NLRI
  int vlen = 2 + 1 + 1 + (int)r->nh_len + 1 + (int)r->nlri_len;

  int hlen = 0;
  // MP_REACH is optional non-transitive => 0x80
  if(put_attr_hdr(out, outlen, PA_FLAG_OPT, PA_MP_REACH, (uint16_t)vlen, &hlen) < 0) return -1;
  if(outlen < hlen + vlen) return -1;

  uint8_t* p = out + hlen;
  p = put_u16(p, r->afi);
  *p++ = r->safi;
  *p++ = r->nh_len;
  memcpy(p, r->nh, r->nh_len); p += r->nh_len;
  *p++ = 0; // SNPA len
  if(r->nlri_len){
    memcpy(p, r->nlri, r->nlri_len);
    p += r->nlri_len;
  }
  return (int)(p - out);
}

static int encode_mp_unreach(uint8_t* out, int outlen, const mp_unreach_t* u){
  if(!u) return 0;
  if(!u->withdrawn && u->withdrawn_len) return -1;

  // Value: AFI(2) + SAFI(1) + withdrawn
  int vlen = 2 + 1 + (int)u->withdrawn_len;

  int hlen = 0;
  // MP_UNREACH is optional non-transitive => 0x80
  if(put_attr_hdr(out, outlen, PA_FLAG_OPT, PA_MP_UNREACH, (uint16_t)vlen, &hlen) < 0) return -1;
  if(outlen < hlen + vlen) return -1;

  uint8_t* p = out + hlen;
  p = put_u16(p, u->afi);
  *p++ = u->safi;
  if(u->withdrawn_len){
    memcpy(p, u->withdrawn, u->withdrawn_len);
    p += u->withdrawn_len;
  }
  return (int)(p - out);
}

// Returns UPDATE payload length (excluding 19-byte BGP header) or -1.
int mp_update_encode(uint8_t* out, int outlen,
                     const bgp_attrs_t* attrs,
                     bool is_ebgp, uint32_t local_asn,
                     const mp_reach_t* reach,
                     const mp_unreach_t* unreach)
{
  if(!out || outlen < 4) return -1;

  // must carry at least one of reach/unreach
  if(!reach && !unreach) return -1;

  uint8_t* p = out;

  // Withdrawn Routes Length (classic) = 0 (MP uses MP_UNREACH)
  *p++ = 0; *p++ = 0;

  // Total Path Attribute Length placeholder
  uint8_t* palen_ptr = p;
  *p++ = 0; *p++ = 0;
  uint8_t* pa_start = p;

  // ---- Required attrs for most stacks ----
  int n = encode_origin(p, outlen - (int)(p - out), 0 /*IGP*/);
  if(n < 0) return -1;
  p += n;

  n = encode_as_path(p, outlen - (int)(p - out), is_ebgp, local_asn);
  if(n < 0) return -1;
  p += n;

  // LOCAL_PREF: iBGP only
  if(!is_ebgp){
    uint32_t lp = (attrs && attrs->has_local_pref) ? attrs->local_pref : 100;
    n = encode_local_pref(p, outlen - (int)(p - out), lp);
    if(n < 0) return -1;
    p += n;
  }

  // Extended Communities (attr code 16, optional transitive 0xC0) — RTs for EVPN/VPLS/VPNv4
  if(attrs && attrs->has_ext_communities && attrs->ext_community_count > 0){
    int vlen = attrs->ext_community_count * 8;
    int hlen = 0;
    if(put_attr_hdr(p, outlen - (int)(p-out), 0xC0, 16, (uint16_t)vlen, &hlen) < 0) return -1;
    if(outlen - (int)(p-out) < hlen + vlen) return -1;
    uint8_t* ev = p + hlen;
    for(int i = 0; i < attrs->ext_community_count; i++){
      memcpy(ev + i*8, attrs->ext_communities[i], 8);
    }
    p += hlen + vlen;
  }

  // ---- MP attributes ----
  // convention: MP_UNREACH then MP_REACH
  n = encode_mp_unreach(p, outlen - (int)(p - out), unreach);
  if(n < 0) return -1;
  p += n;

  n = encode_mp_reach(p, outlen - (int)(p - out), reach);
  if(n < 0) return -1;
  p += n;

  // Fill Total Path Attribute Length
  uint16_t palen = (uint16_t)(p - pa_start);
  palen_ptr[0] = (uint8_t)(palen >> 8);
  palen_ptr[1] = (uint8_t)(palen);

  // NLRI (classic) empty for MP UPDATE
  return (int)(p - out);
}
