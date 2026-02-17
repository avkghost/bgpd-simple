#pragma once
#include <netinet/in.h>

#include "bgp/core.h"
#include "bgp/peer.h"
#include "bgp/attrs.h"

int  afi_ipv4u_withdraw_one(bgp_peer_t* p, struct in_addr pfx, uint8_t plen);
int  afi_ipv4u_announce_one(bgp_peer_t* p, struct in_addr pfx, uint8_t plen, const bgp_attrs_t* a);

// export helpers
void afi_ipv4u_advertise_peer(bgp_core_t* c, bgp_peer_t* p);
void afi_ipv4u_export_prefix_all(bgp_core_t* c, struct in_addr pfx, uint8_t plen);
void afi_ipv4u_export_all(bgp_core_t* c);
