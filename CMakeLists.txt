cmake_minimum_required(VERSION 3.16)
project(bgpd C)

# ── compile_commands.json (for clangd / clang-tidy) ──────────────────────────
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ── Language standard & compile flags ────────────────────────────────────────
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
add_compile_options(-Wall -Wextra -Wpedantic -Werror -O2)

# ── Global include path ───────────────────────────────────────────────────────
include_directories(include)

# ═══════════════════════════════════════════════════════════════════════════════
# Module: infra — logging, utilities, timers, sockets
# ═══════════════════════════════════════════════════════════════════════════════
add_library(mod_infra OBJECT
  src/log.c
  src/util.c
  src/timer_wheel.c
  src/sock.c
)

# ═══════════════════════════════════════════════════════════════════════════════
# Module: platform — event loop (epoll / kqueue) + netlink / MPLS stubs
# ═══════════════════════════════════════════════════════════════════════════════
add_library(mod_platform OBJECT
  $<IF:$<PLATFORM_ID:Linux>,src/event_epoll.c,src/event_kqueue.c>
  $<IF:$<PLATFORM_ID:Linux>,src/netlink_linux.c,src/netlink_stub.c>
  $<IF:$<PLATFORM_ID:Linux>,src/interface_linux.c,src/interface_stub.c>
  $<IF:$<PLATFORM_ID:Linux>,src/mpls_netlink_linux.c,src/mpls_stub.c>
)

# ═══════════════════════════════════════════════════════════════════════════════
# Module: encoding — BGP wire format (attributes, UPDATE, MP-BGP, EVPN, VPLS)
# ═══════════════════════════════════════════════════════════════════════════════
add_library(mod_encoding OBJECT
  src/attrs.c
  src/update.c
  src/update_wire.c
  src/mp_update.c
  src/mpbgp.c
  src/evpn.c
  src/vpls.c
  src/vpn.c
  src/extcomm.c
  src/nlri.c
  src/update6.c
)

# ═══════════════════════════════════════════════════════════════════════════════
# Module: rib — Adj-RIB-In storage and best-path selection (IPv4 & IPv6)
# ═══════════════════════════════════════════════════════════════════════════════
add_library(mod_rib OBJECT
  src/rib.c
  src/rib6.c
)

# ═══════════════════════════════════════════════════════════════════════════════
# Module: policy — prefix-lists, route-maps, VRF database
# ═══════════════════════════════════════════════════════════════════════════════
add_library(mod_policy OBJECT
  src/policy.c
  src/vrf.c
)

# ═══════════════════════════════════════════════════════════════════════════════
# Module: routing — decision process, FIB programming, AFI export helpers (IPv4 & IPv6)
# ═══════════════════════════════════════════════════════════════════════════════
add_library(mod_routing OBJECT
  src/decision.c
  src/decision6.c
  src/afi_ipv4u.c
  src/afi_ipv6u.c
  src/core.c
  src/core_vpn.c
)

# ═══════════════════════════════════════════════════════════════════════════════
# Module: protocol — BGP FSM, peer management, message handling
# ═══════════════════════════════════════════════════════════════════════════════
add_library(mod_protocol OBJECT
  src/fsm.c
  src/msg.c
  src/peer.c
  src/bgp.c
  src/signals.c
  src/debug.c
)

# ═══════════════════════════════════════════════════════════════════════════════
# Module: config — configuration file lexer + parser
# ═══════════════════════════════════════════════════════════════════════════════
add_library(mod_config OBJECT
  src/cfg_lex.c
  src/cfg_parse.c
  src/cfg_write.c
)

# ═══════════════════════════════════════════════════════════════════════════════
# Module: cli — VTY control-plane CLI (UNIX-domain socket)
# ═══════════════════════════════════════════════════════════════════════════════
add_library(mod_cli OBJECT
  src/cli.c
)

# ═══════════════════════════════════════════════════════════════════════════════
# Executable — link all modules together
# ═══════════════════════════════════════════════════════════════════════════════
add_executable(bgpd
  src/main.c
  $<TARGET_OBJECTS:mod_infra>
  $<TARGET_OBJECTS:mod_platform>
  $<TARGET_OBJECTS:mod_encoding>
  $<TARGET_OBJECTS:mod_rib>
  $<TARGET_OBJECTS:mod_policy>
  $<TARGET_OBJECTS:mod_routing>
  $<TARGET_OBJECTS:mod_protocol>
  $<TARGET_OBJECTS:mod_config>
  $<TARGET_OBJECTS:mod_cli>
)

target_link_libraries(bgpd pthread)

