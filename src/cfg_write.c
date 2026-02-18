#include "bgp/core.h"
#include "bgp/bgp.h"
#include "bgp/peer.h"
#include "bgp/vrf.h"
#include "bgp/log.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <ctype.h>

/**
 * Convert interface name to Cisco-like format for serialization.
 * Converts kernel names (lo0, lo1) to Cisco format (loopback 0, loopback 1).
 *
 * @param name      Input interface name (e.g., "lo0", "eth0")
 * @param buf       Output buffer
 * @param buflen    Output buffer length
 */
static void interface_name_to_cisco(const char* name, char* buf, size_t buflen)
{
  if (!name || !buf || buflen == 0) return;

  /* Check if this is a loopback interface (lo0, lo1, lo2, etc.) */
  if (strlen(name) >= 3 && name[0] == 'l' && name[1] == 'o' && isdigit(name[2])) {
    /* Extract the number part (lo0 -> 0, lo1 -> 1, etc.) */
    snprintf(buf, buflen, "loopback %s", &name[2]);
    return;
  }

  /* For other interfaces, use the name as-is */
  strncpy(buf, name, buflen - 1);
  buf[buflen - 1] = '\0';
}

/**
 * Serialize BGP configuration to a text file in Cisco-like format.
 * Reconstructs running configuration from core state.
 *
 * @param path      Output file path (overwritten)
 * @param core      BGP core state to serialize
 * @return 0 on success, -1 on error
 */
int bgp_save_config(const char* path, bgp_core_t* core)
{
  if (!path || !core) {
    log_msg(BGP_LOG_ERROR, "bgp_save_config: invalid arguments");
    return -1;
  }

  FILE* f = fopen(path, "w");
  if (!f) {
    log_msg(BGP_LOG_ERROR, "Failed to open %s for writing: %m", path);
    return -1;
  }

  /* Header comment */
  time_t now = time(NULL);
  fprintf(f, "! BGP Configuration\n");
  fprintf(f, "! Generated: %s", ctime(&now));
  fprintf(f, "!\n");

  /* Write prefix-lists from policy database */
  if (core->pol.plist_count > 0) {
    fprintf(f, "! Prefix-lists\n");
    for (int i = 0; i < core->pol.plist_count; i++) {
      prefix_list_t* pl = &core->pol.plists[i];
      if (pl->name[0] == '\0') continue;

      for (int j = 0; j < pl->rule_count; j++) {
        const prefix_list_rule_t* rule = &pl->rules[j];
        fprintf(f, "ip prefix-list %s seq %u %s %s",
                pl->name, rule->seq, rule->permit ? "permit" : "deny",
                inet_ntoa(rule->pfx));
        if (rule->plen < 32) {
          fprintf(f, "/%u", rule->plen);
        }
        if (rule->le > 0 && rule->le != rule->plen) {
          fprintf(f, " le %u", rule->le);
        }
        fprintf(f, "\n");
      }
    }
    fprintf(f, "!\n");
  }

  /* Write route-maps from policy database */
  if (core->pol.rmap_count > 0) {
    fprintf(f, "! Route-maps\n");
    for (int i = 0; i < core->pol.rmap_count; i++) {
      route_map_t* rm = &core->pol.rmaps[i];
      if (rm->name[0] == '\0') continue;

      for (int j = 0; j < rm->ent_count; j++) {
        const route_map_entry_t* entry = &rm->ents[j];
        fprintf(f, "route-map %s %s %u\n", rm->name,
                entry->permit ? "permit" : "deny", entry->seq);

        /* Write match clauses */
        if (entry->match_plist[0] != '\0') {
          fprintf(f, "  match ip address prefix-list %s\n", entry->match_plist);
        }

        /* Write set clauses */
        if (entry->set_local_pref) {
          fprintf(f, "  set local-preference %u\n", entry->local_pref);
        }
        if (entry->set_med) {
          fprintf(f, "  set metric %u\n", entry->med);
        }
        if (entry->set_next_hop_self) {
          fprintf(f, "  set ip next-hop self\n");
        }

        fprintf(f, "!\n");
      }
    }
  }

  /* Write network interfaces */
  if (core->interface_count > 0) {
    fprintf(f, "! Network Interfaces\n");
    for (int i = 0; i < core->interface_count && i < 64; i++) {
      interface_cfg_t* iface = &core->interfaces[i];
      if (iface->name[0] == '\0') continue;

      char cisco_name[64];
      interface_name_to_cisco(iface->name, cisco_name, sizeof(cisco_name));
      fprintf(f, "interface %s\n", cisco_name);

      if (iface->description[0] != '\0')
        fprintf(f, "  description \"%s\"\n", iface->description);

      if (iface->addr_v4.s_addr != 0)
        fprintf(f, "  ip address %s/%u\n",
                inet_ntoa(iface->addr_v4), iface->plen_v4);

      if (memcmp(&iface->addr_v6, &in6addr_any, 16) != 0) {
        char addr_str[64];
        inet_ntop(AF_INET6, &iface->addr_v6, addr_str, sizeof(addr_str));
        fprintf(f, "  ipv6 address %s/%u\n", addr_str, iface->plen_v6);
      }

      if (iface->mtu != 0 && iface->mtu != 1500)
        fprintf(f, "  mtu %u\n", iface->mtu);

      if (!iface->shutdown)
        fprintf(f, "  no shutdown\n");
      else
        fprintf(f, "  shutdown\n");

      fprintf(f, "!\n");
    }
  }

  /* Write BGP router global config */
  if (core->local_asn != 0) {
    fprintf(f, "router bgp %u\n", core->local_asn);

    if (core->router_id.s_addr != 0)
      fprintf(f, "  bgp router-id %s\n", inet_ntoa(core->router_id));

    if (core->cluster_id.s_addr != 0)
      fprintf(f, "  bgp cluster-id %s\n", inet_ntoa(core->cluster_id));

    /* Write neighbors */
    for (int i = 0; i < core->peer_count && i < 64; i++) {
      bgp_peer_t* p = core->peers[i];
      if (!p) continue;

      fprintf(f, "  neighbor %s remote-as %u\n",
              inet_ntoa(p->addr), p->remote_asn_cfg);

      if (p->description[0] != '\0')
        fprintf(f, "  neighbor %s description \"%s\"\n",
                inet_ntoa(p->addr), p->description);

      if (p->is_rr_client)
        fprintf(f, "  neighbor %s route-reflector-client\n",
                inet_ntoa(p->addr));

      /* Global route-map assignments */
      if (p->rmap_in[0] != '\0')
        fprintf(f, "  neighbor %s route-map %s in\n", inet_ntoa(p->addr), p->rmap_in);
      if (p->rmap_out[0] != '\0')
        fprintf(f, "  neighbor %s route-map %s out\n", inet_ntoa(p->addr), p->rmap_out);
    }

    /* Write address-family sections with networks and neighbor activations */

    /* IPv4 Unicast - only if there are networks OR activated neighbors */
    bool has_ipv4_nets = false;
    for (int i = 0; i < core->network_count; i++) {
      if (core->networks[i].af == 1) {
        has_ipv4_nets = true;
        break;
      }
    }
    bool has_ipv4_peers = false;
    for (int i = 0; i < core->peer_count && i < 64; i++) {
      if (core->peers[i] && core->peers[i]->af_ipv4u_active) {
        has_ipv4_peers = true;
        break;
      }
    }

    if (has_ipv4_nets || has_ipv4_peers) {
      fprintf(f, "  address-family ipv4 unicast\n");

      /* Write networks */
      for (int i = 0; i < core->network_count; i++) {
        const core_network_t* net = &core->networks[i];
        if (net->af != 1) continue;

        char buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &net->prefix.addr4, buf, sizeof(buf));
        fprintf(f, "    network %s/%u\n", buf, net->plen);
      }

      /* Write neighbor activations */
      for (int i = 0; i < core->peer_count && i < 64; i++) {
        bgp_peer_t* p = core->peers[i];
        if (!p || !p->af_ipv4u_active) continue;

        fprintf(f, "    neighbor %s activate\n", inet_ntoa(p->addr));
      }

      fprintf(f, "  exit-address-family\n");
    }

    /* IPv6 Unicast - only if there are networks OR activated neighbors */
    bool has_ipv6_nets = false;
    for (int i = 0; i < core->network_count; i++) {
      if (core->networks[i].af == 2) {
        has_ipv6_nets = true;
        break;
      }
    }
    bool has_ipv6_peers = false;
    for (int i = 0; i < core->peer_count && i < 64; i++) {
      if (core->peers[i] && core->peers[i]->af_ipv6u_active) {
        has_ipv6_peers = true;
        break;
      }
    }

    if (has_ipv6_nets || has_ipv6_peers) {
      fprintf(f, "  address-family ipv6 unicast\n");

      /* Write networks */
      for (int i = 0; i < core->network_count; i++) {
        const core_network_t* net = &core->networks[i];
        if (net->af != 2) continue;

        char buf[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &net->prefix.addr6, buf, sizeof(buf));
        fprintf(f, "    network %s/%u\n", buf, net->plen);
      }

      /* Write neighbor activations for IPv6 */
      for (int i = 0; i < core->peer_count && i < 64; i++) {
        bgp_peer_t* p = core->peers[i];
        if (!p || !p->af_ipv6u_active) continue;

        fprintf(f, "    neighbor %s activate\n", inet_ntoa(p->addr));
      }

      fprintf(f, "  exit-address-family\n");
    }

    /* VPNv4 - networks with af=3, grouped by VRF */
    bool has_vpnv4_nets = false;
    for (int i = 0; i < core->network_count; i++) {
      if (core->networks[i].af == 3) {
        has_vpnv4_nets = true;
        break;
      }
    }
    if (has_vpnv4_nets) {
      /* Collect unique VRF names */
      char vrfs[32][64];
      int vrf_count = 0;
      for (int i = 0; i < core->network_count; i++) {
        if (core->networks[i].af != 3) continue;

        const char* vrf_name = core->networks[i].vrf_name;
        bool found = false;
        for (int j = 0; j < vrf_count; j++) {
          if (strcmp(vrfs[j], vrf_name) == 0) {
            found = true;
            break;
          }
        }
        if (!found && vrf_count < 32) {
          strncpy(vrfs[vrf_count], vrf_name, 63);
          vrfs[vrf_count][63] = '\0';
          vrf_count++;
        }
      }

      /* Write each VRF's networks */
      for (int v = 0; v < vrf_count; v++) {
        fprintf(f, "  address-family ipv4 vrf %s\n", vrfs[v]);
        for (int i = 0; i < core->network_count; i++) {
          const core_network_t* net = &core->networks[i];
          if (net->af != 3) continue;
          if (strcmp(net->vrf_name, vrfs[v]) != 0) continue;

          char buf[INET_ADDRSTRLEN];
          inet_ntop(AF_INET, &net->prefix.addr4, buf, sizeof(buf));
          fprintf(f, "    network %s/%u\n", buf, net->plen);
        }
        fprintf(f, "  exit-address-family\n");
      }
    }

    /* EVPN address-family */
    bool has_evpn = false;
    for (int i = 0; i < core->peer_count && i < 64; i++) {
      if (core->peers[i] && core->peers[i]->af_evpn_active) {
        has_evpn = true;
        break;
      }
    }
    if (has_evpn) {
      fprintf(f, "  address-family l2vpn evpn\n");
      for (int i = 0; i < core->peer_count && i < 64; i++) {
        bgp_peer_t* p = core->peers[i];
        if (!p || !p->af_evpn_active) continue;
        fprintf(f, "    neighbor %s activate\n", inet_ntoa(p->addr));
      }
      fprintf(f, "  exit-address-family\n");
    }

    /* VPLS address-family */
    bool has_vpls = false;
    for (int i = 0; i < core->peer_count && i < 64; i++) {
      if (core->peers[i] && core->peers[i]->af_vpls_active) {
        has_vpls = true;
        break;
      }
    }
    if (has_vpls) {
      fprintf(f, "  address-family l2vpn vpls\n");
      for (int i = 0; i < core->peer_count && i < 64; i++) {
        bgp_peer_t* p = core->peers[i];
        if (!p || !p->af_vpls_active) continue;
        fprintf(f, "    neighbor %s activate\n", inet_ntoa(p->addr));
      }
      fprintf(f, "  exit-address-family\n");
    }

    fprintf(f, "!\n");
  }

  fclose(f);
  log_msg(BGP_LOG_INFO, "Configuration saved to %s", path);
  return 0;
}
