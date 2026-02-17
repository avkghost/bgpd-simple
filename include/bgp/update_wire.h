#pragma once
#include <stdint.h>

typedef struct {
  const uint8_t* withdrawn;
  int withdrawn_len;

  const uint8_t* attrs;
  int attrs_len;

  const uint8_t* nlri;
  int nlri_len;
} update_wire_t;

int update_wire_split(const uint8_t* msg, int msglen, update_wire_t* out);
