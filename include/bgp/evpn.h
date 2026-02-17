/**
 * @file evpn.h
 * @brief EVPN NLRI encoders — AFI=25 SAFI=70 (RFC 7432).
 *
 * Each function encodes a single EVPN route-type NLRI into the caller-supplied
 * buffer.  The bytes written are intended to be placed directly inside the
 * value field of an MP_REACH_NLRI attribute (attribute code 14).
 *
 * Wire format per route type:
 *   Octet 0    : Route Type (1–5)
 *   Octet 1    : Length of the remaining value in bytes
 *   Octets 2…  : Type-specific fields
 *
 * Route Distinguisher format (all types): RFC 4364 Type 0 —
 *   [0x0000 (2)] [ASN (2)] [assigned-number (4)]
 *
 * @return Number of bytes written on success, or -1 on error (buffer too
 *         small or invalid arguments).
 */
#pragma once
#include <stdint.h>
#include <netinet/in.h>

/**
 * @brief Encode an EVPN Type 1 (Ethernet Auto-Discovery) NLRI.
 *
 * Advertises reachability for a given ESI + Ethernet Tag.  Used for fast
 * convergence and aliasing.  The ESI is set to the zero ESI (all-zeros).
 *
 * @param out     Output buffer.
 * @param outlen  Size of @p out in bytes.
 * @param rd_asn  2-octet ASN component of the RD.
 * @param rd_val  4-octet assigned-number component of the RD.
 * @param vni     VNI used as Ethernet Tag ID.
 * @param label   20-bit MPLS label value.
 * @return Bytes written, or -1 on error.
 */
int evpn_nlri_type1_ead(uint8_t *out, int outlen,
                         uint16_t rd_asn, uint32_t rd_val,
                         uint32_t vni, uint32_t label);

/**
 * @brief Encode an EVPN Type 2 (MAC/IP Advertisement) NLRI.
 *
 * Carries a MAC address and an optional IPv4 address bound to it for a given
 * VNI.  The ESI is set to zero (single-homed attachment).
 *
 * @param out     Output buffer.
 * @param outlen  Size of @p out in bytes.
 * @param rd_asn  2-octet ASN component of the RD.
 * @param rd_val  4-octet assigned-number component of the RD.
 * @param vni     VNI used as Ethernet Tag ID.
 * @param mac     6-byte MAC address (must not be NULL).
 * @param ip4     Optional IPv4 address to bind; pass NULL to omit.
 * @param label   20-bit MPLS label value.
 * @return Bytes written, or -1 on error.
 */
int evpn_nlri_type2_mac_ip(uint8_t *out, int outlen,
                            uint16_t rd_asn, uint32_t rd_val,
                            uint32_t vni,
                            const uint8_t mac[6],
                            const struct in_addr *ip4,
                            uint32_t label);

/**
 * @brief Encode an EVPN Type 3 (Inclusive Multicast Ethernet Tag) NLRI.
 *
 * Advertises participation in the BUM (Broadcast/Unknown-unicast/Multicast)
 * flooding domain for the specified VNI.
 *
 * @param out        Output buffer.
 * @param outlen     Size of @p out in bytes.
 * @param rd_asn     2-octet ASN component of the RD.
 * @param rd_val     4-octet assigned-number component of the RD.
 * @param vni        VNI used as Ethernet Tag ID.
 * @param originator Originating router's IPv4 address.
 * @return Bytes written, or -1 on error.
 */
int evpn_nlri_type3_imet(uint8_t *out, int outlen,
                          uint16_t rd_asn, uint32_t rd_val,
                          uint32_t vni,
                          struct in_addr originator);

/**
 * @brief Encode an EVPN Type 5 (IP Prefix) NLRI (IPv4 only).
 *
 * Carries an IPv4 prefix for inter-subnet routing across VXLANs.
 *
 * @param out     Output buffer.
 * @param outlen  Size of @p out in bytes.
 * @param rd_asn  2-octet ASN component of the RD.
 * @param rd_val  4-octet assigned-number component of the RD.
 * @param vni     VNI used as Ethernet Tag ID.
 * @param pfx     IPv4 prefix address (must not be NULL).
 * @param plen    Prefix length in bits (0–32).
 * @param gw_ip   Gateway IP address for the prefix.
 * @return Bytes written, or -1 on error.
 */
int evpn_nlri_type5_ip_prefix(uint8_t *out, int outlen,
                               uint16_t rd_asn, uint32_t rd_val,
                               uint32_t vni,
                               const struct in_addr *pfx, uint8_t plen,
                               struct in_addr gw_ip);

/* ── NLRI decoder types ─────────────────────────────────────────────────── */

/** Decoded representation of a single EVPN route. */
typedef struct {
  uint8_t route_type;    /* 1=EAD, 2=MAC/IP, 3=IMET, 5=IP-prefix */
  uint16_t rd_asn;
  uint32_t rd_val;
  uint32_t eth_tag;      /* Ethernet Tag ID (= VNI for VXLAN) */

  /* Type 2: MAC/IP */
  uint8_t mac[6];
  uint8_t mac_len;       /* 0 if not present */

  /* Type 2/5: IP */
  struct in_addr ip4;
  uint8_t ip4_len;       /* 0 if not present */

  /* Type 3: originator */
  struct in_addr originator;

  /* Type 5: IP prefix */
  struct in_addr pfx;
  uint8_t plen;
  struct in_addr gw;

  /* MPLS label (type 1/2) */
  uint32_t label;
} evpn_route_t;

/**
 * @brief Decode one EVPN NLRI entry (type + length + value).
 *
 * @param out  Caller-supplied output struct.
 * @param buf  Pointer to the first byte of the TLV (the Route Type byte).
 * @param len  Remaining bytes available in @p buf.
 * @return Bytes consumed (> 0) on success, -1 on error / unknown type.
 */
int evpn_nlri_decode_one(evpn_route_t *out, const uint8_t *buf, int len);

/**
 * @brief Extract the MP_REACH / MP_UNREACH NLRI blob for AFI=25 SAFI=70
 *        from the raw path-attributes bytes of a BGP UPDATE.
 *
 * @param reach_nlri     Set to pointer inside @p attrs on success (or NULL).
 * @param reach_len      Set to byte length of the reach blob.
 * @param unreach_nlri   Set to pointer for withdraw blob (or NULL).
 * @param unreach_len    Set to withdraw blob length.
 * @param attrs          Raw path-attributes bytes.
 * @param attrs_len      Length of @p attrs.
 */
void evpn_extract_nlri_blobs(const uint8_t **reach_nlri,   int *reach_len,
                              const uint8_t **unreach_nlri, int *unreach_len,
                              const uint8_t *attrs, int attrs_len);
