#include "bgp/attrs.h"
#include <string.h>
#include <arpa/inet.h>

void attrs_init(bgp_attrs_t* a){
  memset(a, 0, sizeof(*a));
  a->origin = 2; // INCOMPLETE default
}

static int get_u16(const uint8_t* p){ return (p[0]<<8) | p[1]; }
static uint32_t get_u32(const uint8_t* p){ return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3]; }

int attrs_decode(bgp_attrs_t* a, const uint8_t* p, int len, bool is_ebgp){
  attrs_init(a);
  int off = 0;

  while(off < len){
    if(off + 2 > len) return -1;
    uint8_t flags = p[off+0];
    uint8_t code  = p[off+1];
    off += 2;

    bool extlen = (flags & 0x10) != 0;
    int alen = 0;
    if(extlen){
      if(off + 2 > len) return -1;
      alen = get_u16(p+off); off += 2;
    } else {
      if(off + 1 > len) return -1;
      alen = p[off]; off += 1;
    }
    if(off + alen > len) return -1;
    const uint8_t* v = p + off;

    switch(code){
      case 1: // ORIGIN
        if(alen != 1) return -1;
        a->origin = v[0];
        break;

      case 2: { // AS_PATH — full segment list decode (RFC 4271 §4.3)
        a->has_as_path = true;
        a->as_path_len = 0;
        int seg_off = 0;
        while (seg_off + 2 <= alen) {
          /* uint8_t seg_type = v[seg_off]; */ /* 1=AS_SET 2=AS_SEQUENCE */
          uint8_t seg_len  = v[seg_off + 1];
          seg_off += 2;
          for (int k = 0; k < (int)seg_len && seg_off + 2 <= alen; k++, seg_off += 2) {
            uint32_t asn = (uint32_t)((v[seg_off] << 8) | v[seg_off + 1]);
            if (a->as_path_len == 0) a->as_path_first = asn;
            if (a->as_path_len < AS_PATH_MAX)
              a->as_path[a->as_path_len++] = asn;
          }
        }
        break;
      }

      case 3: // NEXT_HOP
        if(alen != 4) return -1;
        memcpy(&a->next_hop, v, 4);
        a->has_next_hop = true;
        break;

      case 4: // MED
        if(alen != 4) return -1;
        a->med = get_u32(v);
        a->has_med = true;
        break;

      case 5: // LOCAL_PREF
        if(alen != 4) return -1;
        a->local_pref = get_u32(v);
        a->has_local_pref = true;
        break;

      case 8: // COMMUNITY
        a->has_community = true;
        a->community_count = 0;
        for(int i=0; i+4 <= alen && a->community_count < 32; i+=4){
          a->community[a->community_count++] = get_u32(v+i);
        }
        break;

      case 9: // ORIGINATOR_ID (RR)
        if(alen != 4) return -1;
        memcpy(&a->originator_id, v, 4);
        a->has_originator_id = true;
        break;

      case 10: // CLUSTER_LIST (RR)
        a->has_cluster_list = true;
        a->cluster_count = 0;
        for(int i=0; i+4 <= alen && a->cluster_count < 32; i+=4){
          memcpy(&a->cluster_list[a->cluster_count++], v+i, 4);
        }
        break;

      case 16: // EXTENDED COMMUNITIES (RFC 4360) — carries RTs for EVPN/VPNv4/VPLS
        a->has_ext_communities = true;
        a->ext_community_count = 0;
        for(int i=0; i+8 <= alen && a->ext_community_count < 32; i+=8){
          memcpy(a->ext_communities[a->ext_community_count++], v+i, 8);
        }
        break;

      default:
        // ignore unsupported attributes (but real BGP must treat unknown transitive differently)
        break;
    }

    off += alen;
  }

  // eBGP default local_pref not used; iBGP typically sets local_pref if missing
  (void)is_ebgp;
  return 0;
}

static int put_attr_hdr(uint8_t* out, int outlen, uint8_t flags, uint8_t code, int alen){
  if(alen > 255){
    /* Extended-length encoding: set flag bit 0x10, use 2-byte length field */
    flags |= 0x10;
    int need = 2 + 2 + alen;
    if(need > outlen) return -1;
    out[0]=flags; out[1]=code;
    out[2]=(uint8_t)(alen>>8); out[3]=(uint8_t)alen;
    return 4;
  }
  int need = 2 + 1 + alen;
  if(need > outlen) return -1;
  out[0]=flags; out[1]=code; out[2]=(uint8_t)alen;
  return 3;
}

int attrs_encode(uint8_t* out, int outlen, const bgp_attrs_t* a, bool include_local_pref){
  int off = 0;

  // ORIGIN (well-known mandatory) flags: transitive
  {
    int h = put_attr_hdr(out+off, outlen-off, 0x40, 1, 1); if(h<0) return -1;
    out[off+h]=a->origin;
    off += h+1;
  }

  // AS_PATH (well-known mandatory) — encode full segment list (RFC 4271 §4.3)
  {
    int path_len = a->has_as_path ? a->as_path_len : 0;
    // One AS_SEQUENCE segment: [type=2][count][asn0_hi][asn0_lo]...
    int seg_bytes = (path_len > 0) ? (2 + path_len * 2) : 0;
    int h = put_attr_hdr(out+off, outlen-off, 0x40, 2, seg_bytes); if(h<0) return -1;
    if (path_len > 0) {
      uint8_t* q = out + off + h;
      *q++ = 2;             /* AS_SEQUENCE */
      *q++ = (uint8_t)path_len;
      for (int i = 0; i < path_len; i++) {
        *q++ = (uint8_t)(a->as_path[i] >> 8);
        *q++ = (uint8_t)(a->as_path[i]);
      }
    }
    off += h + seg_bytes;
  }

  // NEXT_HOP (well-known mandatory for IPv4 unicast; omitted for MP-BGP families
  // where the next-hop is carried in MP_REACH_NLRI attribute code 14).
  if(a->has_next_hop){
    int h = put_attr_hdr(out+off, outlen-off, 0x40, 3, 4); if(h<0) return -1;
    memcpy(out+off+h, &a->next_hop, 4);
    off += h+4;
  }

  // LOCAL_PREF (well-known discretionary, iBGP only) – controlled by include_local_pref
  if(include_local_pref && a->has_local_pref){
    int h = put_attr_hdr(out+off, outlen-off, 0x40, 5, 4); if(h<0) return -1;
    out[off+h+0] = (uint8_t)(a->local_pref>>24);
    out[off+h+1] = (uint8_t)(a->local_pref>>16);
    out[off+h+2] = (uint8_t)(a->local_pref>>8);
    out[off+h+3] = (uint8_t)(a->local_pref);
    off += h+4;
  }

  // MED
  if(a->has_med){
    int h = put_attr_hdr(out+off, outlen-off, 0x80 /* optional */, 4, 4); if(h<0) return -1;
    out[off+h+0] = (uint8_t)(a->med>>24);
    out[off+h+1] = (uint8_t)(a->med>>16);
    out[off+h+2] = (uint8_t)(a->med>>8);
    out[off+h+3] = (uint8_t)(a->med);
    off += h+4;
  }

  // Communities
  if(a->has_community && a->community_count>0){
    int alen = a->community_count * 4;
    int h = put_attr_hdr(out+off, outlen-off, 0xC0 /* optional+transitive */, 8, alen);
    if(h<0) return -1;
    for(int i=0;i<a->community_count;i++){
      uint32_t v=a->community[i];
      out[off+h+i*4+0]=(uint8_t)(v>>24);
      out[off+h+i*4+1]=(uint8_t)(v>>16);
      out[off+h+i*4+2]=(uint8_t)(v>>8);
      out[off+h+i*4+3]=(uint8_t)(v);
    }
    off += h+alen;
  }

  // RR attrs (optional)
  if(a->has_originator_id){
    int h = put_attr_hdr(out+off, outlen-off, 0x80, 9, 4); if(h<0) return -1;
    memcpy(out+off+h, &a->originator_id, 4);
    off += h+4;
  }
  if(a->has_cluster_list && a->cluster_count>0){
    int alen = a->cluster_count*4;
    int h = put_attr_hdr(out+off, outlen-off, 0x80, 10, alen); if(h<0) return -1;
    for(int i=0;i<a->cluster_count;i++){
      memcpy(out+off+h+i*4, &a->cluster_list[i], 4);
    }
    off += h+alen;
  }

  // Extended Communities (optional transitive, code 16) — RTs for EVPN/VPNv4/VPLS
  if(a->has_ext_communities && a->ext_community_count > 0){
    int alen = a->ext_community_count * 8;
    // flags: optional(0x80) + transitive(0x40) = 0xC0
    int h = put_attr_hdr(out+off, outlen-off, 0xC0, 16, alen); if(h<0) return -1;
    for(int i=0; i<a->ext_community_count; i++){
      memcpy(out+off+h+i*8, a->ext_communities[i], 8);
    }
    off += h+alen;
  }

  return off;
}
