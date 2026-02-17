#pragma once
#include <stdio.h>
#include <stdlib.h>

//static void* dbg_calloc(size_t n, size_t sz, const char* file, int line){
//  size_t total = n * sz;
//  if(total > (1u<<20)) { // >1MB
//    fprintf(stderr, "CALLOC %zu x %zu = %zu at %s:%d\n", n, sz, total, file, line);
//  }
//  return calloc(n, sz);
//}

//#define calloc(n,sz) dbg_calloc((n),(sz),__FILE__,__LINE__)
