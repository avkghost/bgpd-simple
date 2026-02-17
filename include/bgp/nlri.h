#pragma once
/**
 * @file nlri.h
 * @brief NLRI wire-format encode/decode primitives (RFC 4271, RFC 4760).
 *
 * These helpers encode/decode packed prefix lists used in both the
 * classic IPv4 NLRI field of UPDATE and in the MP_REACH/MP_UNREACH
 * attribute value for all address families.
 *
 * IPv4 NLRI (RFC 4271 §4.3):
 *   <plen(1)> <prefix(ceil(plen/8))>
 *
 * IPv6 NLRI (RFC 4760 §4):
 *   same layout, prefix is 16-byte base
 *
 * VPNv4 NLRI (RFC 4364 §4.3.4):
 *   <total_bits(1)> <label(3)> <rd(8)> <prefix(ceil(pfx_bits/8))>
 *   total_bits = (3+8)*8 + pfx_bits
 */

#include <stdint.h>
#include <netinet/in.h>

/* ── IPv4 prefix list ──────────────────────────────────────────────────── */

typedef struct {
  struct in_addr pfx;
  uint8_t plen;
} nlri_pfx4_t;

/**
 * Decode a packed IPv4 prefix list of exactly @p len bytes.
 * @return 0 on success, -1 on error (truncated / too many prefixes).
 */
int nlri_decode4(nlri_pfx4_t* out, int max, int* count,
                 const uint8_t* buf, int len);

/**
 * Encode @p count IPv4 prefixes into @p out.
 * @return bytes written, or -1 on overflow.
 */
int nlri_encode4(uint8_t* out, int outlen,
                 const nlri_pfx4_t* arr, int count);

/* ── IPv6 prefix list ──────────────────────────────────────────────────── */

typedef struct {
  struct in6_addr pfx;
  uint8_t plen;
} nlri_pfx6_t;

/**
 * Decode a packed IPv6 prefix list of exactly @p len bytes.
 * @return 0 on success, -1 on error.
 */
int nlri_decode6(nlri_pfx6_t* out, int max, int* count,
                 const uint8_t* buf, int len);

/**
 * Encode @p count IPv6 prefixes.
 * @return bytes written, or -1 on overflow.
 */
int nlri_encode6(uint8_t* out, int outlen,
                 const nlri_pfx6_t* arr, int count);

/* ── VPNv4 NLRI ────────────────────────────────────────────────────────── */

typedef struct {
  uint32_t label;          /* 20-bit label value */
  uint16_t rd_asn;         /* RD type-0 ASN field */
  uint32_t rd_val;         /* RD type-0 NN field */
  struct in_addr pfx;
  uint8_t plen;
} nlri_vpnv4_t;

/**
 * Decode one VPNv4 NLRI entry from @p buf.
 * @return bytes consumed (> 0), or -1 on error.
 */
int nlri_decode_vpnv4_one(nlri_vpnv4_t* out, const uint8_t* buf, int len);

/**
 * Encode one VPNv4 NLRI entry into @p out.
 * @return bytes written, or -1 on overflow.
 */
int nlri_encode_vpnv4_one(uint8_t* out, int outlen,
                          const nlri_vpnv4_t* n);
