/* src/nlri.c — NLRI wire-format encode/decode (RFC 4271, RFC 4760, RFC 4364) */

#include "bgp/nlri.h"
#include <string.h>

/* ── IPv4 ─────────────────────────────────────────────────────────────── */

int nlri_decode4(nlri_pfx4_t* out, int max, int* count,
                 const uint8_t* buf, int len)
{
  int off = 0;
  *count = 0;
  while (off < len) {
    if (*count >= max) return -1;
    if (off + 1 > len) return -1;

    uint8_t plen  = buf[off++];
    if (plen > 32) return -1;
    int bytes = (plen + 7) / 8;
    if (off + bytes > len) return -1;

    uint8_t tmp[4] = {0, 0, 0, 0};
    memcpy(tmp, buf + off, (size_t)bytes);

    out[*count].pfx.s_addr = 0;
    memcpy(&out[*count].pfx, tmp, 4);
    out[*count].plen = plen;
    (*count)++;
    off += bytes;
  }
  return 0;
}

int nlri_encode4(uint8_t* out, int outlen,
                 const nlri_pfx4_t* arr, int count)
{
  int off = 0;
  for (int i = 0; i < count; i++) {
    uint8_t plen  = arr[i].plen;
    int     bytes = (plen + 7) / 8;
    if (off + 1 + bytes > outlen) return -1;
    out[off++] = plen;
    uint8_t tmp[4] = {0, 0, 0, 0};
    memcpy(tmp, &arr[i].pfx, 4);
    memcpy(out + off, tmp, (size_t)bytes);
    off += bytes;
  }
  return off;
}

/* ── IPv6 ─────────────────────────────────────────────────────────────── */

int nlri_decode6(nlri_pfx6_t* out, int max, int* count,
                 const uint8_t* buf, int len)
{
  int off = 0;
  *count = 0;
  while (off < len) {
    if (*count >= max) return -1;
    if (off + 1 > len) return -1;

    uint8_t plen  = buf[off++];
    if (plen > 128) return -1;
    int bytes = (plen + 7) / 8;
    if (off + bytes > len) return -1;

    memset(&out[*count].pfx, 0, 16);
    memcpy(&out[*count].pfx, buf + off, (size_t)bytes);
    out[*count].plen = plen;
    (*count)++;
    off += bytes;
  }
  return 0;
}

int nlri_encode6(uint8_t* out, int outlen,
                 const nlri_pfx6_t* arr, int count)
{
  int off = 0;
  for (int i = 0; i < count; i++) {
    uint8_t plen  = arr[i].plen;
    int     bytes = (plen + 7) / 8;
    if (off + 1 + bytes > outlen) return -1;
    out[off++] = plen;
    uint8_t tmp[16];
    memset(tmp, 0, 16);
    memcpy(tmp, &arr[i].pfx, 16);
    memcpy(out + off, tmp, (size_t)bytes);
    off += bytes;
  }
  return off;
}

/* ── VPNv4 ────────────────────────────────────────────────────────────── */

/*
 * VPNv4 NLRI on-wire layout (RFC 4364 §4.3.4):
 *   total_bits(1) : (3+8)*8 + pfx_bits  = 88 + pfx_bits
 *   label(3)      : 20-bit label in high bits, low 3 bits are TC+S
 *   rd(8)         : RD type-0: 0x0000(2) + asn(2) + nn(4)
 *   prefix(N)     : ceil(pfx_bits/8) bytes, high-order bits
 */

int nlri_decode_vpnv4_one(nlri_vpnv4_t* out, const uint8_t* buf, int len)
{
  if (len < 1) return -1;
  int total_bits = buf[0];
  int total_bytes = (total_bits + 7) / 8;
  if (1 + total_bytes > len) return -1;

  /* minimum: label(3) + rd(8) = 11 bytes → 88 bits */
  if (total_bits < 88) return -1;

  const uint8_t* p = buf + 1;

  /* label: 20 high bits of 24-bit field (top 3 bytes) */
  out->label = ((uint32_t)p[0] << 12) | ((uint32_t)p[1] << 4) | (p[2] >> 4);
  p += 3;

  /* rd type 0: 0x0000 (2) + asn (2) + nn (4) */
  /* (ignoring type field bytes — accept type 0 only) */
  /* uint16_t rd_type = (p[0]<<8)|p[1]; */
  out->rd_asn = (uint16_t)((p[2] << 8) | p[3]);
  out->rd_val = ((uint32_t)p[4] << 24) | ((uint32_t)p[5] << 16) |
                ((uint32_t)p[6] << 8)  | p[7];
  p += 8;

  int pfx_bits  = total_bits - 88;
  if (pfx_bits < 0 || pfx_bits > 32) return -1;
  int pfx_bytes = (pfx_bits + 7) / 8;

  if (p + pfx_bytes > buf + 1 + total_bytes) return -1;

  out->plen       = (uint8_t)pfx_bits;
  out->pfx.s_addr = 0;
  uint8_t tmp[4]  = {0, 0, 0, 0};
  memcpy(tmp, p, (size_t)pfx_bytes);
  memcpy(&out->pfx, tmp, 4);

  return 1 + total_bytes;
}

int nlri_encode_vpnv4_one(uint8_t* out, int outlen, const nlri_vpnv4_t* n)
{
  if (n->plen > 32) return -1;
  int pfx_bytes  = (n->plen + 7) / 8;
  int total_bits = 88 + n->plen;             /* (3+8)*8 + pfx_bits */
  int needed     = 1 + 3 + 8 + pfx_bytes;
  if (needed > outlen) return -1;

  uint8_t* p = out;

  /* total prefix length in bits */
  *p++ = (uint8_t)total_bits;

  /* label: 3 bytes, label in top 20 bits, S-bit=1 */
  uint32_t lbl = (n->label & 0xFFFFF);
  *p++ = (uint8_t)(lbl >> 12);
  *p++ = (uint8_t)(lbl >> 4);
  *p++ = (uint8_t)((lbl << 4) | 0x01);    /* S=1 bottom-of-stack */

  /* rd type 0: 0x0000 + asn(2) + nn(4) */
  *p++ = 0x00; *p++ = 0x00;
  *p++ = (uint8_t)(n->rd_asn >> 8);
  *p++ = (uint8_t)(n->rd_asn);
  *p++ = (uint8_t)(n->rd_val >> 24);
  *p++ = (uint8_t)(n->rd_val >> 16);
  *p++ = (uint8_t)(n->rd_val >> 8);
  *p++ = (uint8_t)(n->rd_val);

  /* prefix */
  uint8_t tmp[4] = {0, 0, 0, 0};
  memcpy(tmp, &n->pfx, 4);
  memcpy(p, tmp, (size_t)pfx_bytes);
  p += pfx_bytes;

  return (int)(p - out);
}
