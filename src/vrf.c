#include "bgp/vrf.h"
#include <string.h>
#include <stdlib.h>

void vrf_db_init(vrf_db_t* db){ memset(db,0,sizeof(*db)); }

void vrf_db_destroy(vrf_db_t* db){
  if(!db) return;
  free(db->vrfs);
  db->vrfs = NULL;
  db->vrf_count = db->vrf_cap = 0;
}

vrf_t* vrf_get(vrf_db_t* db, const char* name, int create){
  for(int i=0;i<db->vrf_count;i++) if(strcmp(db->vrfs[i].name,name)==0) return &db->vrfs[i];
  if(!create) return NULL;

  if(db->vrf_count == db->vrf_cap){
    int ncap = (db->vrf_cap == 0) ? 8 : db->vrf_cap * 2;
    vrf_t* n = (vrf_t*)realloc(db->vrfs, (size_t)ncap * sizeof(vrf_t));
    if(!n) return NULL;
    db->vrfs = n;
    db->vrf_cap = ncap;
  }

  vrf_t* v = &db->vrfs[db->vrf_count++];
  memset(v,0,sizeof(*v));
  strncpy(v->name,name,sizeof(v->name)-1);
  v->table_id = 0; // must be configured or auto-assigned later
  return v;
}
