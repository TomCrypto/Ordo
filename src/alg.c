/*===-- alg.c -----------------------------------------*- generic -*- C -*-===*/

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

/*===----------------------------------------------------------------------===*/

void pswap8 (uint8_t  *a, uint8_t  *b) { uint8_t  c = *a; *a = *b; *b = c; }
void pswap16(uint16_t *a, uint16_t *b) { uint16_t c = *a; *a = *b; *b = c; }
void pswap32(uint32_t *a, uint32_t *b) { uint32_t c = *a; *a = *b; *b = c; }
void pswap64(uint64_t *a, uint64_t *b) { uint64_t c = *a; *a = *b; *b = c; }

size_t smin(size_t a, size_t b) { return (a < b) ? a : b; }
size_t smax(size_t a, size_t b) { return (a > b) ? a : b; }

uint16_t rol16(uint16_t x, int n)
{
    return (uint16_t)((x << n) | (x >> (16 - n)));
}

uint16_t ror16(uint16_t x, int n)
{
    return (uint16_t)((x >> n) | (x << (16 - n)));
}

uint32_t rol32(uint32_t x, int n)
{
    return (uint32_t)((x << n) | (x >> (32 - n)));
}

uint32_t ror32(uint32_t x, int n)
{
    return (uint32_t)((x >> n) | (x << (32 - n)));
}

uint64_t rol64(uint64_t x, int n)
{
    return (uint64_t)((x << n) | (x >> (64 - n)));
}

uint64_t ror64(uint64_t x, int n)
{
    return (uint64_t)((x >> n) | (x << (64 - n)));
}

/*===----------------------------------------------------------------------===*/

int pad_check(const unsigned char *buffer, uint8_t padding)
{
    size_t t;

    if (padding == 0)
        return 0;

    for (t = 0; t < padding; t++)
        if (buffer[t] != padding) return 0;

    return 1;
}

void xor_buffer(unsigned char *dst, const unsigned char *src, size_t len)
{
    while (len--) *(dst++) ^= *(src++);
}

void inc_buffer(unsigned char *buffer, size_t len)
{
    size_t carry = 1;
    size_t t = 0;

    while (carry && (++t <= len)) carry = (++*(buffer + t - 1) == 0);
}
