#include "bgp/policy.h"
#include <string.h>
#include <stdlib.h>

void policy_init(policy_db_t* p){
  memset(p, 0, sizeof(*p));
}

void policy_destroy(policy_db_t* p){
  if(!p) return;
  free(p->plists);
  free(p->rmaps);
  p->plists = NULL;
  p->rmaps = NULL;
  p->plist_count = p->plist_cap = 0;
  p->rmap_count  = p->rmap_cap  = 0;
}

prefix_list_t* policy_get_plist(policy_db_t* db, const char* name, bool create){
  for(int i=0;i<db->plist_count;i++) if(strcmp(db->plists[i].name,name)==0) return &db->plists[i];
  if(!create) return NULL;

  if(db->plist_count == db->plist_cap){
    int ncap = (db->plist_cap == 0) ? 8 : db->plist_cap * 2;
    prefix_list_t* n = (prefix_list_t*)realloc(db->plists, (size_t)ncap * sizeof(prefix_list_t));
    if(!n) return NULL;
    db->plists = n;
    db->plist_cap = ncap;
  }

  prefix_list_t* pl = &db->plists[db->plist_count++];
  memset(pl,0,sizeof(*pl));
  strncpy(pl->name,name,sizeof(pl->name)-1);
  return pl;
}

route_map_t* policy_get_rmap(policy_db_t* db, const char* name, bool create){
  for(int i=0;i<db->rmap_count;i++) if(strcmp(db->rmaps[i].name,name)==0) return &db->rmaps[i];
  if(!create) return NULL;

  if(db->rmap_count == db->rmap_cap){
    int ncap = (db->rmap_cap == 0) ? 8 : db->rmap_cap * 2;
    route_map_t* n = (route_map_t*)realloc(db->rmaps, (size_t)ncap * sizeof(route_map_t));
    if(!n) return NULL;
    db->rmaps = n;
    db->rmap_cap = ncap;
  }

  route_map_t* rm = &db->rmaps[db->rmap_count++];
  memset(rm,0,sizeof(*rm));
  strncpy(rm->name,name,sizeof(rm->name)-1);
  return rm;
}

/**
 * @brief Return true if @p candidate_pfx / @p candidate_plen is contained
 *        within rule base prefix @p r and satisfies the ge/le length bounds.
 *
 * Cisco prefix-list matching rules (RFC 4271 §5.1.3 interpretation):
 *  1. The candidate prefix must be a subnet of (or equal to) the rule base
 *     prefix: i.e. candidate_plen >= r->plen AND the top r->plen bits match.
 *  2. If ge is set, candidate_plen >= ge.
 *  3. If le is set, candidate_plen <= le.
 *  4. If neither ge nor le is set, exact match is required (plen == r->plen).
 */
static bool rule_matches(const prefix_list_rule_t* r,
                         struct in_addr pfx, uint8_t plen)
{
  /* Step 1: candidate plen must be >= base plen (contained-in check) */
  if(plen < r->plen) return false;

  /* Step 2: the top r->plen bits of the two addresses must match */
  if(r->plen > 0){
    uint32_t mask = (r->plen == 32) ? 0xFFFFFFFFu
                                    : (~0u << (32 - r->plen));
    if((ntohl(pfx.s_addr) & mask) != (ntohl(r->pfx.s_addr) & mask))
      return false;
  } else {
    /* r->plen == 0: 0.0.0.0/0 — any prefix matches the containment check */
    (void)pfx;
  }

  /* Step 3: length bounds */
  if(r->ge == 0 && r->le == 0){
    /* No ge/le — exact prefix-length match required */
    return plen == r->plen;
  }
  if(r->ge && plen < r->ge) return false;
  if(r->le && plen > r->le) return false;

  return true;
}

bool prefix_list_permit(const prefix_list_t* pl, struct in_addr pfx, uint8_t plen){
  if(!pl) return true; /* no list configured => permit all */

  for(int i = 0; i < pl->rule_count; i++){
    const prefix_list_rule_t* r = &pl->rules[i];
    if(rule_matches(r, pfx, plen)) return r->permit;
  }

  /* implicit deny — matches Cisco IOS behaviour */
  return false;
}

bool route_map_apply(const policy_db_t* db, const char* rmap_name,
                     struct in_addr pfx, uint8_t plen, bgp_attrs_t* attrs){
  if(!rmap_name || !rmap_name[0]) return true; // no map => permit
  const route_map_t* rm = NULL;
  for(int i=0;i<db->rmap_count;i++) if(strcmp(db->rmaps[i].name,rmap_name)==0) rm=&db->rmaps[i];
  if(!rm) return true;

  // evaluate entries by seq order as stored
  for(int i=0;i<rm->ent_count;i++){
    const route_map_entry_t* e = &rm->ents[i];

    // match prefix-list if configured
    if(e->match_plist[0]){
      const prefix_list_t* pl = NULL;
      for(int j=0;j<db->plist_count;j++) if(strcmp(db->plists[j].name,e->match_plist)==0) pl=&db->plists[j];
      if(!prefix_list_permit(pl, pfx, plen)) continue; // match failed
    }

    /* ── apply set actions ─────────────────────────────────────── */
    if (e->set_local_pref) {
      attrs->has_local_pref = true;
      attrs->local_pref = e->local_pref;
    }
    if (e->set_med) {
      attrs->has_med = true;
      attrs->med = e->med;
    }
    if (e->set_next_hop_self) {
      attrs->set_next_hop_self = true;
    }
    if (e->set_community) {
      if (e->community_additive && attrs->has_community) {
        for (int ci = 0; ci < e->community_count; ci++) {
          bool found = false;
          for (int cj = 0; cj < attrs->community_count && !found; cj++)
            found = (attrs->community[cj] == e->community[ci]);
          if (!found && attrs->community_count < 32)
            attrs->community[attrs->community_count++] = e->community[ci];
        }
      } else {
        int cnt = e->community_count < 32 ? e->community_count : 32;
        memcpy(attrs->community, e->community, (size_t)cnt * sizeof(uint32_t));
        attrs->community_count = cnt;
      }
      attrs->has_community = (attrs->community_count > 0);
    }
    if (e->set_as_path_prepend && e->prepend_count > 0 &&
        attrs->as_path_len + e->prepend_count <= AS_PATH_MAX) {
      int shift = e->prepend_count;
      memmove(&attrs->as_path[shift], attrs->as_path,
              (size_t)attrs->as_path_len * sizeof(uint32_t));
      for (int pi = 0; pi < shift; pi++)
        attrs->as_path[pi] = e->prepend_asn;
      attrs->as_path_len += shift;
      attrs->has_as_path = true;
    }
    return e->permit;
  }

  // no entry matched => deny by default like Cisco route-map
  return false;
}
