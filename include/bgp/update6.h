#pragma once
/**
 * @file update6.h
 * @brief IPv6 unicast MP-BGP UPDATE encode/decode (AFI=2 SAFI=1, RFC 4760).
 *
 * IPv6 routes are carried in MP_REACH_NLRI (attr 14) / MP_UNREACH_NLRI (attr 15).
 * The next-hop in MP_REACH is a 16-byte IPv6 address (or 32 bytes when a
 * link-local is also present, but we emit only the global).
 */

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
#include "bgp/attrs.h"
#include "bgp/nlri.h"

#define BGP_UPDATE6_MAX_PREFIXES 256

typedef struct {
  /* Withdrawn prefixes (from MP_UNREACH_NLRI) */
  nlri_pfx6_t withdrawn[BGP_UPDATE6_MAX_PREFIXES];
  int         withdrawn_count;

  /* Path attributes */
  bgp_attrs_t attrs;

  /* Announced prefixes + IPv6 next-hop (from MP_REACH_NLRI) */
  nlri_pfx6_t nlri[BGP_UPDATE6_MAX_PREFIXES];
  int         nlri_count;

  struct in6_addr next_hop;   /* global next-hop from MP_REACH */
  bool            has_nh;
} bgp_update6_t;

void update6_init(bgp_update6_t* u);

/**
 * Decode IPv6 MP-BGP UPDATE (full BGP message including 19-byte header).
 * Fills @p u with prefixes and attributes.
 * @return 0 on success, -1 on parse error.
 */
int update6_decode(bgp_update6_t* u, const uint8_t* msg, int msglen,
                   bool is_ebgp);

/**
 * Encode an IPv6 MP_REACH_NLRI announcement into a complete UPDATE payload
 * (without the 19-byte BGP header).
 *
 * @param out        Output buffer.
 * @param outlen     Buffer size.
 * @param nh6        IPv6 next-hop address.
 * @param pfx        Array of prefixes to announce.
 * @param pfx_count  Number of prefixes.
 * @param attrs      BGP path attributes.
 * @param is_ebgp    True for eBGP sessions.
 * @param local_asn  Local ASN for AS_PATH construction.
 * @return Bytes written, or -1 on error.
 */
int update6_encode_reach(uint8_t* out, int outlen,
                         const struct in6_addr* nh6,
                         const nlri_pfx6_t* pfx, int pfx_count,
                         const bgp_attrs_t* attrs,
                         bool is_ebgp, uint32_t local_asn);

/**
 * Encode an IPv6 MP_UNREACH_NLRI withdrawal into a complete UPDATE payload.
 *
 * @return Bytes written, or -1 on error.
 */
int update6_encode_unreach(uint8_t* out, int outlen,
                           const nlri_pfx6_t* pfx, int pfx_count,
                           bool is_ebgp, uint32_t local_asn);
