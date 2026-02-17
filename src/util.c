#include "bgp/util.h"
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

void strlcpy0(char* dst, const char* src, size_t dstsz){
  if(dstsz == 0) return;
  if(!src){
    dst[0] = 0;
    return;
  }

  size_t n = strlen(src);
  if(n >= dstsz) n = dstsz - 1;

  memcpy(dst, src, n);
  dst[n] = 0;
}

uint64_t mono_time_ms(void){
#if defined(CLOCK_MONOTONIC)
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
#else
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
#endif

  return (uint64_t)ts.tv_sec * 1000ULL +
         (uint64_t)(ts.tv_nsec / 1000000ULL);
}

void hexdump(FILE* out, const void* data, size_t len, int with_ascii){
  const uint8_t* p = (const uint8_t*)data;

  for(size_t i = 0; i < len; i += 16){
    fprintf(out, "%08zx  ", i);

    for(size_t j = 0; j < 16; j++){
      if(i + j < len)
        fprintf(out, "%02x ", p[i + j]);
      else
        fprintf(out, "   ");
    }

    if(with_ascii){
      fprintf(out, " ");
      for(size_t j = 0; j < 16 && i + j < len; j++){
        uint8_t c = p[i + j];
        fputc(isprint(c) ? (char)c : '.', out);
      }
    }

    fputc('\n', out);
  }
}
