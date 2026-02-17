#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

void strlcpy0(char* dst, const char* src, size_t dstsz);
uint64_t mono_time_ms(void);
void hexdump(FILE* out, const void* data, size_t len, int with_ascii);
