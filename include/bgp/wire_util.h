/**
 * @file wire_util.h
 * @brief Internal BGP wire-encoding helpers (not part of the public API).
 *
 * Provides inline big-endian serialisation primitives shared across the BGP
 * message encoding translation units (attrs, mp_update, evpn, vpls, …).
 *
 * All functions are declared static inline to avoid ODR issues when the header
 * is included from multiple translation units.
 */
#pragma once
#include <stdint.h>
#include <string.h>

/** Write a 16-bit big-endian value at @p p and return a pointer past it. */
static inline uint8_t *wire_put_u16(uint8_t *p, const uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v);
    return p + 2;
}

/** Write a 32-bit big-endian value at @p p and return a pointer past it. */
static inline uint8_t *wire_put_u32(uint8_t *p, const uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >>  8);
    p[3] = (uint8_t)(v);
    return p + 4;
}

/**
 * @brief Write an RFC 3032 MPLS label stack entry (3 bytes).
 *
 * Encodes the 20-bit label value in the top bits of a 3-byte field with TC=0,
 * S bit (bottom-of-stack) set per the @p is_bos flag, and TTL=0.
 *
 * @param p       Destination buffer (must have ≥ 3 bytes available).
 * @param label   20-bit label value (bits above bit 19 are ignored).
 * @param is_bos  Non-zero to set the bottom-of-stack (S) bit.
 * @return Pointer past the written bytes.
 */
static inline uint8_t *wire_put_mpls_label(uint8_t *p,
                                            const uint32_t label,
                                            const int is_bos)
{
    /*
     * BGP 3-byte label stack entry layout (RFC 3032 / RFC 8277):
     *   byte 0: label[19:12]
     *   byte 1: label[11:4]
     *   byte 2: label[3:0] | TC[2:0] | S[0]
     *
     * The 24-bit field is: [label(20)][TC(3)][S(1)]
     * Label occupies bits 23..4, TC bits 3..1, S (BoS) bit 0.
     * There is NO TTL byte — that is only in the 4-byte IP/MPLS header.
     */
    uint32_t v = (label & 0x000FFFFFU) << 4; /* label in bits 23..4 */
    if (is_bos) {
        v |= 0x01U; /* S bit is bit 0 of the 24-bit field */
    }
    p[0] = (uint8_t)(v >> 16);
    p[1] = (uint8_t)(v >>  8);
    p[2] = (uint8_t)(v);
    return p + 3;
}

/**
 * @brief Write an RFC 4364 Route Distinguisher Type 0 (ASN:NN, 8 bytes).
 *
 * Format: [type=0 (2 bytes)] [asn (2 bytes)] [nn (4 bytes)]
 *
 * @param p   Destination buffer (must have ≥ 8 bytes available).
 * @param asn 2-octet ASN field.
 * @param nn  4-octet assigned-number field.
 * @return Pointer past the written bytes.
 */
static inline uint8_t *wire_put_rd_type0(uint8_t *p,
                                          const uint16_t asn,
                                          const uint32_t nn)
{
    p = wire_put_u16(p, 0);   /* RD type 0 */
    p = wire_put_u16(p, asn);
    p = wire_put_u32(p, nn);
    return p;
}
