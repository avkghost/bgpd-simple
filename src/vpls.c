/**
 * @file vpls.c
 * @brief VPLS (L2VPN) NLRI encoder — AFI=25 SAFI=65 (RFC 4761).
 *
 * Encodes a VPLS NLRI entry placed inside an MP_REACH_NLRI attribute
 * (attribute code 14), per RFC 4761 §3.2.2.
 *
 * RFC 4761 §3.2.2 VPLS NLRI on-wire layout (19 bytes total):
 *
 *   [Length = 0x0011 = 17 octets (2 bytes)]
 *   [RD Type 0: 0x0000 (2) + ASN (2) + NN (4)]
 *   [VE-ID (2)]
 *   [VE-Block-Offset (2)]
 *   [VE-Block-Size (2)]
 *   [Label-Base (3)]
 *
 * The 2-byte Length field is in OCTETS (not bits) and covers only the
 * value bytes (not itself):
 *   RD(8) + VE-ID(2) + VBO(2) + VBS(2) + Label(3) = 17 octets.
 */

#include "bgp/vpls.h"
#include "bgp/wire_util.h"

#include <stdint.h>

int vpls_nlri_min(uint8_t *const out, const int outlen,
                  const uint16_t rd_asn, const uint32_t rd_nn,
                  const uint16_t ve_id,
                  const uint32_t label)
{
    if (!out) {
        return -1;
    }

    /*
     * 2-byte length (0x0011 = 17 octets of value) +
     * RD(8) + VE-ID(2) + VBO(2) + VBS(2) + Label(3) = 19 bytes total.
     */
    if (outlen < 19) {
        return -1;
    }

    uint8_t *p = out;

    p = wire_put_u16(p, 17);                /* Length in octets (RFC 4761 §3.2.2) */
    p = wire_put_rd_type0(p, rd_asn, rd_nn);
    p = wire_put_u16(p, ve_id);             /* VE-ID */
    p = wire_put_u16(p, ve_id);             /* VE-Block-Offset = VE-ID (block starts here) */
    p = wire_put_u16(p, 1);                /* VE-Block-Size = 1 (single VE in block) */
    p = wire_put_mpls_label(p, label, /*is_bos=*/1); /* Label-Base */

    return (int)(p - out);
}
