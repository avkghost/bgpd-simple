#pragma once
#include "bgp/bgp.h"

int bgp_load_config(bgp_config_t* out, const char* path);
