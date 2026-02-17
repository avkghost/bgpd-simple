#pragma once
#include <stdint.h>
#include <netinet/in.h>
#include <stdbool.h>

// Push MPLS labels on an IPv4 route (LWTUNNEL_ENCAP_MPLS)
// Installs into an IPv4 routing table (e.g. VRF table).
int nl_route_replace_v4_mpls_encap(struct in_addr pfx, uint8_t plen,
                                   struct in_addr nh,
                                   const uint32_t* labels, int label_count,
                                   int table);

// MPLS label route (AF_MPLS): inlabel -> via inet nh, optionally outlabel stack (swap / push)
int nl_mpls_route_replace(uint32_t in_label,
                          struct in_addr nh,
                          const uint32_t* out_labels, int out_label_count);

int nl_mpls_route_delete(uint32_t in_label);
