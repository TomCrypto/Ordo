/*===-- alg.c -----------------------------------------*- generic -*- C -*-===*/

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

#include "ordo/internal/alg.h"

/*===----------------------------------------------------------------------===*/

void pswap8 (uint8_t  *a, uint8_t  *b)
{
    uint8_t  c = *a;
    *a = *b; *b = c;
}

void pswap16(uint16_t *a, uint16_t *b)
{
    uint16_t c = *a;
    *a = *b; *b = c;
}

void pswap32(uint32_t *a, uint32_t *b)
{
    uint32_t c = *a;
    *a = *b; *b = c;
}

void pswap64(uint64_t *a, uint64_t *b)
{
    uint64_t c = *a;
    *a = *b; *b = c;
}

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

size_t limit_constrain(size_t in, size_t min, size_t max, size_t mul)
{
    if (in <= min)
        return min;

    if (in >= max)
        return max;

    return in + ((in % mul) ? mul - in % mul : 0);
}

int limit_check(size_t in, size_t min, size_t max, size_t mul)
{
    return (in == limit_constrain(in, min, max, mul));
}

/*===----------------------------------------------------------------------===*/

size_t pad_check(const void *buffer, size_t len)
{
    /* PCKS #7 padding verification (constant time) */

    if ((len > 0) && (len < 256))
    {
        uint8_t block[255] = {0};
        memcpy(block, buffer, len);

        {
            uint8_t padding = block[len - 1]; /* Final byte. */
            uint8_t acc = (padding == 0) || (padding > len);
            size_t t, pad_offset = len - (size_t)padding;

            for (t = pad_offset; t < len; ++t)
                acc |= (block[t] ^ padding);

            if (pad_offset == 0) pad_offset = len;
            return (acc == 0) ? pad_offset : 0;
        }
    }

    return 0;
}

void xor_buffer(void * RESTRICT _dst, const void * RESTRICT _src, size_t len)
{
    const unsigned char *src = (const unsigned char *)_src;
    unsigned char *dst = (unsigned char *)_dst;
    while (len--) *(dst++) ^= *(src++);
}

void inc_buffer(unsigned char *buffer, size_t len)
{
    size_t carry = 1;
    size_t t = 0;

    while (carry && (++t <= len)) carry = (++*(buffer + t - 1) == 0);
}
