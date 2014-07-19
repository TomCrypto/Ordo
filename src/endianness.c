/*===-- endianness.c ----------------------------------*- generic -*- C -*-===*/

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

#include "ordo/misc/endianness.h"

/*===----------------------------------------------------------------------===*/

#if !(defined(ORDO_LITTLE_ENDIAN) || defined(ORDO_BIG_ENDIAN))
    #error "Endianness not defined!"
#endif

static uint16_t bswap16(uint16_t x)
{
    return ((x << 8) & 0xFF00)
         | ((x >> 8) & 0x00FF);
}

static uint32_t bswap32(uint32_t x)
{
    return ((x << 24) & 0xFF000000)
         | ((x <<  8) & 0x00FF0000)
         | ((x >>  8) & 0x0000FF00)
         | ((x >> 24) & 0x000000FF);
}

static uint64_t bswap64(uint64_t x)
{
    return ((x & UINT64_C(0xFF00000000000000)) >> 56)
         | ((x & UINT64_C(0x00FF000000000000)) >> 40)
         | ((x & UINT64_C(0x0000FF0000000000)) >> 24)
         | ((x & UINT64_C(0x000000FF00000000)) >>  8)
         | ((x & UINT64_C(0x00000000FF000000)) <<  8)
         | ((x & UINT64_C(0x0000000000FF0000)) << 24)
         | ((x & UINT64_C(0x000000000000FF00)) << 40)
         | ((x & UINT64_C(0x00000000000000FF)) << 56);
}

/*===----------------------------------------------------------------------===*/

uint16_t tole16(uint16_t x)
{
    #if defined(ORDO_LITTLE_ENDIAN)
    return x;
    #else
    return bswap16(x);
    #endif
}

uint16_t tobe16(uint16_t x)
{
    #if defined(ORDO_LITTLE_ENDIAN)
    return bswap16(x);
    #else
    return x;
    #endif
}

uint16_t fmle16(uint16_t x)
{
    return tole16(x);
}

uint16_t fmbe16(uint16_t x)
{
    return tobe16(x);
}

uint32_t tole32(uint32_t x)
{
    #if defined(ORDO_LITTLE_ENDIAN)
    return x;
    #else
    return bswap32(x);
    #endif
}

uint32_t tobe32(uint32_t x)
{
    #if defined(ORDO_LITTLE_ENDIAN)
    return bswap32(x);
    #else
    return x;
    #endif
}

uint32_t fmle32(uint32_t x)
{
    return tole32(x);
}

uint32_t fmbe32(uint32_t x)
{
    return tobe32(x);
}

uint64_t tole64(uint64_t x)
{
    #if defined(ORDO_LITTLE_ENDIAN)
    return x;
    #else
    return bswap64(x);
    #endif
}

uint64_t tobe64(uint64_t x)
{
    #if defined(ORDO_LITTLE_ENDIAN)
    return bswap64(x);
    #else
    return x;
    #endif
}

uint64_t fmle64(uint64_t x)
{
    return tole64(x);
}

uint64_t fmbe64(uint64_t x)
{
    return tobe64(x);
}
