// src/mpbgp.c
#include "bgp/mpbgp.h"
#include <string.h>

void caps_init(bgp_caps_t* c){
  if(!c) return;
  memset(c, 0, sizeof(*c));
}
