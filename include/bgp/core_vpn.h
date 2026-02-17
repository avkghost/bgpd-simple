#pragma once
#include "bgp/core.h"
#include "bgp/vpn.h"
#include "bgp/rib.h"   // <-- REQUIRED for rib4_* APIs

void core_on_vpnv4(bgp_core_t* c, bgp_peer_t* from,
                   const vpnv4_update_t* vu);
