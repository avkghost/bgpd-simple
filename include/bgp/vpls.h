/**
 * @file vpls.h
 * @brief VPLS (L2VPN) NLRI encoder — AFI=25 SAFI=65 (RFC 4761).
 *
 * Provides a minimal RFC 4761 §3.2.2 NLRI encoder for L2VPN VPLS.
 * The encoded bytes are intended to be placed inside the value field of an
 * MP_REACH_NLRI attribute (attribute code 14).
 */
#pragma once
#include <stdint.h>

/**
 * @brief Encode a VPLS NLRI per RFC 4761 §3.2.2.
 *
 * Builds the following 19-byte structure:
 *
 *   [Length = 0x0011 = 17 octets (2)] — RFC 4761 §3.2.2 length in octets
 *   [RD Type 0: ASN(2) + NN(4) (8 total)]
 *   [VE-ID (2)]
 *   [VE-Block-Offset = 0 (2)]
 *   [VE-Block-Size   = 1 (2)]
 *   [Label-Base with BoS=1 (3)]
 *
 * @param out     Output buffer (must be ≥ 19 bytes).
 * @param outlen  Size of @p out in bytes.
 * @param rd_asn  2-octet ASN component of the Route Distinguisher.
 * @param rd_nn   4-octet assigned-number component of the Route Distinguisher.
 * @param ve_id   16-bit Virtual Edge identifier.
 * @param label   20-bit MPLS label-base value (must be ≥ 16).
 * @return Bytes written (always 19) on success, or -1 on error.
 */
int vpls_nlri_min(uint8_t *out, int outlen,
                  uint16_t rd_asn, uint32_t rd_nn,
                  uint16_t ve_id, uint32_t label);
