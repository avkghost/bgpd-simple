// src/malloc_trace.c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

void* __real_calloc(size_t n, size_t s);
void* __wrap_calloc(size_t n, size_t s){
  __uint128_t total = (__uint128_t)n * (__uint128_t)s;
  if(total > (1ULL<<30)){ // >1GB
    fprintf(stderr, "HUGE calloc: n=%zu s=%zu total=%llu\n",
            n, s, (unsigned long long)total);
    fflush(stderr);
  }
  return __real_calloc(n, s);
}
