//===-- alg.c -----------------------------------------*- generic -*- C -*-===//

#include "ordo/internal/alg.h"

/// @cond
#include "ordo/internal/implementation.h"
/// @endcond

//===----------------------------------------------------------------------===//

void swap8 (uint8_t  *a, uint8_t  *b) { uint8_t  c = *a; *a = *b; *b = c; }
void swap16(uint16_t *a, uint16_t *b) { uint16_t c = *a; *a = *b; *b = c; }
void swap32(uint32_t *a, uint32_t *b) { uint32_t c = *a; *a = *b; *b = c; }
void swap64(uint64_t *a, uint64_t *b) { uint64_t c = *a; *a = *b; *b = c; }

// Some compilers like to define min and max, don't let them

size_t min_(size_t a, size_t b) { return (a < b) ? a : b; }
size_t max_(size_t a, size_t b) { return (a > b) ? a : b; }

uint16_t rol16(uint16_t x, int n) { return (x << n) | (x >> (16 - n)); }
uint16_t ror16(uint16_t x, int n) { return (x >> n) | (x << (16 - n)); }
uint32_t rol32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }
uint32_t ror32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
uint64_t rol64(uint64_t x, int n) { return (x << n) | (x >> (64 - n)); }
uint64_t ror64(uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }

//===----------------------------------------------------------------------===//

int pad_check(const unsigned char *buffer, uint8_t padding)
{
    size_t t;

    for (t = 0; t < padding; t++)
        if (buffer[t] != padding) return 0;

    return 1;
}

void xor_buffer(void *dst, const void *src, size_t len)
{
    while (len--)
    {
        *(unsigned char *)dst = *(unsigned char *)dst
                              ^ *(unsigned char *)src;

        dst = offset(dst, 1);
        src = offset(src, 1);
    }
}

void inc_buffer(unsigned char *buffer, size_t len)
{
    size_t carry = 1;
    size_t t = 0;

    while (carry && (++t <= len)) carry = (++*(buffer + t - 1) == 0);
}
