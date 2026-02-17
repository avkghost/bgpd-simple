/**
 * @file evpn.c
 * @brief EVPN NLRI encoders (AFI=25 SAFI=70, RFC 7432).
 *
 * Encodes EVPN route types into the NLRI byte string that is placed inside
 * the MP_REACH_NLRI attribute (attribute code 14).  Each encoder returns the
 * total number of bytes written, or -1 on failure (insufficient buffer or
 * invalid arguments).
 *
 * Route type wire format:
 *   [Type (1)] [Length (1)] [Value (Length bytes)]
 *
 * RD format used throughout: Type 0 per RFC 4364 — [0x0000][ASN(2)][NN(4)].
 * ESI: 10 bytes; for locally originated routes we send the zero ESI.
 * MPLS label: 3-byte RFC 3032 stack entry (TC=0, TTL=0).
 */

#include "bgp/evpn.h"
#include "bgp/wire_util.h"

#include <string.h>
#include <stdint.h>

/* MARK: --- Internal helpers --- */

/**
 * @brief Derive an Ethernet Tag ID from a VNI.
 *
 * Per RFC 7432 §8 the Ethernet Tag ID carries the VNI (or VNID in the data-
 * plane sense).  For a simple lab / overlay mapping we use the VNI value
 * directly as the 32-bit tag.
 */
static inline uint32_t eth_tag_from_vni(const uint32_t vni)
{
    return vni;
}

/**
 * @brief Write the minimal prefix bytes for an IPv4 prefix of length @p plen.
 *
 * Only ceil(plen/8) bytes are written; the remaining bits are implicitly zero.
 *
 * @param dst  Destination buffer (must have ≥ ceil(plen/8) bytes).
 * @param src  Pointer to the full 4-byte in_addr.
 * @param plen Prefix length in bits (0–32).
 */
static inline void copy_prefix_bytes(uint8_t *restrict dst,
                                      const struct in_addr *restrict src,
                                      const uint8_t plen)
{
    const int n = (plen + 7) / 8;
    memcpy(dst, src, (size_t)n);
}

/* MARK: --- Public encoders --- */

int evpn_nlri_type1_ead(uint8_t *const out, const int outlen,
                         const uint16_t rd_asn, const uint32_t rd_val,
                         const uint32_t vni, const uint32_t label)
{
    if (!out || outlen < 2) {
        return -1;
    }

    uint8_t *p = out;

    *p++ = 1;                    /* Route Type 1 — Ethernet Auto-Discovery */
    uint8_t *const lenp = p++;   /* Length field filled in at the end       */

    /* RD (8 bytes) */
    if (outlen - (int)(p - out) < 8) { return -1; }
    p = wire_put_rd_type0(p, rd_asn, rd_val);

    /* ESI (10 bytes) — zero ESI for per-EVI EAD */
    if (outlen - (int)(p - out) < 10) { return -1; }
    memset(p, 0, 10);
    p += 10;

    /* Ethernet Tag ID (4 bytes) */
    if (outlen - (int)(p - out) < 4) { return -1; }
    p = wire_put_u32(p, eth_tag_from_vni(vni));

    /* MPLS Label (3 bytes) — bottom-of-stack */
    if (outlen - (int)(p - out) < 3) { return -1; }
    p = wire_put_mpls_label(p, label, /*is_bos=*/1);

    *lenp = (uint8_t)(p - (lenp + 1));
    return (int)(p - out);
}

int evpn_nlri_type2_mac_ip(uint8_t *const out, const int outlen,
                            const uint16_t rd_asn, const uint32_t rd_val,
                            const uint32_t vni,
                            const uint8_t mac[6],
                            const struct in_addr *const ip4,
                            const uint32_t label)
{
    if (!out || !mac) {
        return -1;
    }

    uint8_t *p = out;

    *p++ = 2;                    /* Route Type 2 — MAC/IP Advertisement */
    uint8_t *const lenp = p++;

    /* RD (8 bytes) */
    if (outlen - (int)(p - out) < 8) { return -1; }
    p = wire_put_rd_type0(p, rd_asn, rd_val);

    /* ESI (10 bytes) — zero ESI */
    if (outlen - (int)(p - out) < 10) { return -1; }
    memset(p, 0, 10);
    p += 10;

    /* Ethernet Tag ID (4 bytes) */
    if (outlen - (int)(p - out) < 4) { return -1; }
    p = wire_put_u32(p, eth_tag_from_vni(vni));

    /* MAC Address Length (1 byte = 48 bits) + MAC Address (6 bytes) */
    if (outlen - (int)(p - out) < 7) { return -1; }
    *p++ = 48;
    memcpy(p, mac, 6);
    p += 6;

    /* IP Address Length + IP Address (IPv4: 32 bits + 4 bytes; omitted: 0) */
    if (ip4) {
        if (outlen - (int)(p - out) < 5) { return -1; }
        *p++ = 32;
        memcpy(p, ip4, 4);
        p += 4;
    } else {
        if (outlen - (int)(p - out) < 1) { return -1; }
        *p++ = 0; /* IP Address Length = 0 means no IP */
    }

    /* MPLS Label 1 (3 bytes) — bottom-of-stack when no label 2 */
    if (outlen - (int)(p - out) < 3) { return -1; }
    p = wire_put_mpls_label(p, label, /*is_bos=*/1);

    *lenp = (uint8_t)(p - (lenp + 1));
    return (int)(p - out);
}

int evpn_nlri_type3_imet(uint8_t *const out, const int outlen,
                          const uint16_t rd_asn, const uint32_t rd_val,
                          const uint32_t vni,
                          const struct in_addr originator)
{
    if (!out || outlen < 2) {
        return -1;
    }

    uint8_t *p = out;

    *p++ = 3;                    /* Route Type 3 — Inclusive Multicast ET */
    uint8_t *const lenp = p++;

    /* RD (8 bytes) */
    if (outlen - (int)(p - out) < 8) { return -1; }
    p = wire_put_rd_type0(p, rd_asn, rd_val);

    /* ESI (10 bytes) = 0 */
    if (outlen - (int)(p - out) < 10) { return -1; }
    memset(p, 0, 10);
    p += 10;

    /* Ethernet Tag ID (4 bytes) */
    if (outlen - (int)(p - out) < 4) { return -1; }
    p = wire_put_u32(p, eth_tag_from_vni(vni));

    /* IP Address Length (1 byte = 32 bits) + Originating Router IP (4 bytes) */
    if (outlen - (int)(p - out) < 5) { return -1; }
    *p++ = 32;
    memcpy(p, &originator, 4);
    p += 4;

    /* MPLS Label (3 bytes) — label 0, bottom-of-stack */
    if (outlen - (int)(p - out) < 3) { return -1; }
    p = wire_put_mpls_label(p, 0, /*is_bos=*/1);

    *lenp = (uint8_t)(p - (lenp + 1));
    return (int)(p - out);
}

int evpn_nlri_type5_ip_prefix(uint8_t *const out, const int outlen,
                               const uint16_t rd_asn, const uint32_t rd_val,
                               const uint32_t vni,
                               const struct in_addr *const pfx,
                               const uint8_t plen,
                               const struct in_addr gw_ip)
{
    if (!out || !pfx) {
        return -1;
    }

    const int pfx_bytes = (plen + 7) / 8;

    uint8_t *p = out;

    *p++ = 5;                    /* Route Type 5 — IP Prefix */
    uint8_t *const lenp = p++;

    /* RD (8 bytes) */
    if (outlen - (int)(p - out) < 8) { return -1; }
    p = wire_put_rd_type0(p, rd_asn, rd_val);

    /* ESI (10 bytes) = 0 */
    if (outlen - (int)(p - out) < 10) { return -1; }
    memset(p, 0, 10);
    p += 10;

    /* Ethernet Tag ID (4 bytes) */
    if (outlen - (int)(p - out) < 4) { return -1; }
    p = wire_put_u32(p, eth_tag_from_vni(vni));

    /* IP Prefix Length (1 byte) */
    if (outlen - (int)(p - out) < 1) { return -1; }
    *p++ = plen;

    /* IP Prefix (ceil(plen/8) bytes) */
    if (outlen - (int)(p - out) < pfx_bytes) { return -1; }
    copy_prefix_bytes(p, pfx, plen);
    p += pfx_bytes;

    /* GW IP Length (1 byte = 32 bits) + GW IP (4 bytes, IPv4) */
    if (outlen - (int)(p - out) < 5) { return -1; }
    *p++ = 32;
    memcpy(p, &gw_ip, 4);
    p += 4;

    /* MPLS Label (3 bytes) — label 0, bottom-of-stack */
    if (outlen - (int)(p - out) < 3) { return -1; }
    p = wire_put_mpls_label(p, 0, /*is_bos=*/1);

    *lenp = (uint8_t)(p - (lenp + 1));
    return (int)(p - out);
}

/* ── NLRI decoder ─────────────────────────────────────────────────────────── */

#include <stdbool.h>

static uint16_t get_u16_e(const uint8_t* px){ return (uint16_t)((px[0]<<8)|px[1]); }
static uint32_t get_u32_e(const uint8_t* px){
  return ((uint32_t)px[0]<<24)|((uint32_t)px[1]<<16)|((uint32_t)px[2]<<8)|px[3];
}

int evpn_nlri_decode_one(evpn_route_t *out, const uint8_t *buf, int len)
{
  if (!out || !buf || len < 2) return -1;
  memset(out, 0, sizeof(*out));

  uint8_t rtype = buf[0];
  uint8_t vlen  = buf[1];
  if (2 + (int)vlen > len) return -1;

  const uint8_t *v = buf + 2;
  out->route_type = rtype;

  /* All types begin with RD (8 bytes): type(2) + asn(2) + nn(4). */
  if (vlen < 8) return -1;
  out->rd_asn = get_u16_e(v + 2);
  out->rd_val = get_u32_e(v + 4);
  int off = 8;

  switch (rtype) {
    case 1: {  /* EAD: ESI(10) + EthTag(4) + Label(3) */
      if (vlen < 8 + 10 + 4 + 3) return -1;
      off += 10;  /* skip ESI */
      out->eth_tag = get_u32_e(v + off); off += 4;
      out->label   = ((uint32_t)v[off]<<12)|((uint32_t)v[off+1]<<4)|(v[off+2]>>4);
      break;
    }
    case 2: {  /* MAC/IP: ESI(10)+EthTag(4)+MACLen(1)+MAC(6)+IPLen(1)+IP+Label(3) */
      if (vlen < 8 + 10 + 4 + 1 + 6) return -1;
      off += 10;  /* skip ESI */
      out->eth_tag = get_u32_e(v + off); off += 4;
      uint8_t mlen = v[off++];
      out->mac_len = mlen;
      if (mlen == 48 && off + 6 <= (int)vlen) {
        memcpy(out->mac, v + off, 6);
      }
      off += (mlen + 7) / 8;
      if (off >= (int)vlen) break;
      uint8_t iplen2 = v[off++];
      out->ip4_len = iplen2;
      if (iplen2 == 32 && off + 4 <= (int)vlen) {
        memcpy(&out->ip4, v + off, 4);
      }
      off += (iplen2 + 7) / 8;
      if (off + 3 <= (int)vlen) {
        out->label = ((uint32_t)v[off]<<12)|((uint32_t)v[off+1]<<4)|(v[off+2]>>4);
      }
      break;
    }
    case 3: {  /* IMET: ESI(10)+EthTag(4)+IPLen(1)+IP+Label(3) */
      if (vlen < 8 + 10 + 4 + 1) return -1;
      off += 10;
      out->eth_tag = get_u32_e(v + off); off += 4;
      uint8_t iplen3 = v[off++];
      if (iplen3 == 32 && off + 4 <= (int)vlen) {
        memcpy(&out->originator, v + off, 4);
      }
      off += (iplen3 + 7) / 8;
      if (off + 3 <= (int)vlen) {
        out->label = ((uint32_t)v[off]<<12)|((uint32_t)v[off+1]<<4)|(v[off+2]>>4);
      }
      break;
    }
    case 5: {  /* IP-Prefix: ESI(10)+EthTag(4)+PLen(1)+Pfx+GWLen(1)+GW+Label(3) */
      if (vlen < 8 + 10 + 4 + 1) return -1;
      off += 10;
      out->eth_tag = get_u32_e(v + off); off += 4;
      if (off >= (int)vlen) return -1;
      out->plen = v[off++];
      int pbytes = (out->plen + 7) / 8;
      if (off + pbytes > (int)vlen) return -1;
      uint8_t tmp[4] = {0,0,0,0};
      memcpy(tmp, v + off, (size_t)pbytes);
      memcpy(&out->pfx, tmp, 4);
      off += pbytes;
      if (off >= (int)vlen) break;
      uint8_t gwlen = v[off++];
      if (gwlen == 32 && off + 4 <= (int)vlen) {
        memcpy(&out->gw, v + off, 4);
      }
      off += (gwlen + 7) / 8;
      if (off + 3 <= (int)vlen) {
        out->label = ((uint32_t)v[off]<<12)|((uint32_t)v[off+1]<<4)|(v[off+2]>>4);
      }
      break;
    }
    default:
      return -1;
  }

  return 2 + (int)vlen;
}

void evpn_extract_nlri_blobs(const uint8_t **reach_nlri,   int *reach_len,
                              const uint8_t **unreach_nlri, int *unreach_len,
                              const uint8_t *attrs, int attrs_len)
{
  *reach_nlri   = NULL; *reach_len   = 0;
  *unreach_nlri = NULL; *unreach_len = 0;

  int off = 0;
  while (off < attrs_len) {
    if (off + 2 > attrs_len) return;
    uint8_t flags = attrs[off];
    uint8_t code  = attrs[off+1];
    off += 2;
    bool extlen = (flags & 0x10) != 0;
    int  vlen2  = 0;
    if (extlen) {
      if (off + 2 > attrs_len) return;
      vlen2  = get_u16_e(attrs + off);
      off   += 2;
    } else {
      if (off + 1 > attrs_len) return;
      vlen2  = attrs[off++];
    }
    if (off + vlen2 > attrs_len) return;
    const uint8_t *v = attrs + off;

    if (code == 14 && vlen2 >= 4) {
      uint16_t afi  = get_u16_e(v);
      uint8_t  safi = v[2];
      if (afi == 25 && safi == 70) {
        int p = 3;
        if (p < vlen2) {
          uint8_t nhlen = v[p++];
          p += (int)nhlen;
          if (p < vlen2) {
            uint8_t snpa = v[p++];
            for (int s = 0; s < (int)snpa; s++) {
              if (p >= vlen2) { p = vlen2; break; }
              uint8_t slen = v[p++];
              p += (slen + 1) / 2;
            }
            if (p < vlen2) {
              *reach_nlri = v + p;
              *reach_len  = vlen2 - p;
            }
          }
        }
      }
    } else if (code == 15 && vlen2 >= 3) {
      uint16_t afi  = get_u16_e(v);
      uint8_t  safi = v[2];
      if (afi == 25 && safi == 70 && vlen2 > 3) {
        *unreach_nlri = v + 3;
        *unreach_len  = vlen2 - 3;
      }
    }

    off += vlen2;
  }
}
