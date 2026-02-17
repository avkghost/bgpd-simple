#pragma once
#include <stdint.h>
#include <netinet/in.h>

typedef struct {
  uint32_t asn;
  uint32_t val;  // number part (for ASN:NN)
} rt_asn_t;

typedef struct {
  char name[64];

  // RD: support ASN:NN only in this baseline
  rt_asn_t rd;

  // RT sets
  rt_asn_t import_rts[64];
  int import_count;

  rt_asn_t export_rts[64];
  int export_count;

  // Linux routing table for this VRF
  int table_id;

  // EVPN extras (optional)
  uint32_t vni;
  char bridge[64];
} vrf_t;

typedef struct {
  vrf_t* vrfs;  // heap-allocated
  int vrf_count;
  int vrf_cap;
} vrf_db_t;

void vrf_db_init(vrf_db_t* db);
void vrf_db_destroy(vrf_db_t* db);
vrf_t* vrf_get(vrf_db_t* db, const char* name, int create);
