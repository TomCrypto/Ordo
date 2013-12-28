//===-- sys.c -------------------------------------------*- win32 -*- C -*-===//

#include "ordo/internal/sys.h"

/// @cond
#include "ordo/internal/implementation.h"
/// @endcond

//===----------------------------------------------------------------------===//

// Windows is always little-endian, but sadly does not provide endian.h.

static uint16_t bswap16_(uint16_t x)
{
    return ((x << 8) & 0xFF00)
         | ((x >> 8) & 0x00FF);
}

static uint32_t bswap32_(uint32_t x)
{
    return ((x << 24) & 0xFF000000)
         | ((x <<  8) & 0x00FF0000)
         | ((x >>  8) & 0x0000FF00)
         | ((x >> 24) & 0x000000FF);
}

static uint64_t bswap64_(uint64_t x)
{
    return ((x & (uint64_t)0xFF00000000000000ULL) >> 56)
         | ((x & (uint64_t)0x00FF000000000000ULL) >> 40)
         | ((x & (uint64_t)0x0000FF0000000000ULL) >> 24)
         | ((x & (uint64_t)0x000000FF00000000ULL) >>  8)
         | ((x & (uint64_t)0x00000000FF000000ULL) <<  8)
         | ((x & (uint64_t)0x0000000000FF0000ULL) << 24)
         | ((x & (uint64_t)0x000000000000FF00ULL) << 40)
         | ((x & (uint64_t)0x00000000000000FFULL) << 56);
}

//===----------------------------------------------------------------------===//

uint16_t htole16_(uint16_t x) { return x;           }
uint16_t htobe16_(uint16_t x) { return bswap16_(x); }
uint16_t le16toh_(uint16_t x) { return htole16_(x); }
uint16_t be16toh_(uint16_t x) { return htobe16_(x); }

uint32_t htole32_(uint32_t x) { return x;           }
uint32_t htobe32_(uint32_t x) { return bswap32_(x); }
uint32_t le32toh_(uint32_t x) { return htole32_(x); }
uint32_t be32toh_(uint32_t x) { return htobe32_(x); }

uint64_t htole64_(uint64_t x) { return x;           }
uint64_t htobe64_(uint64_t x) { return bswap64_(x); }
uint64_t le64toh_(uint64_t x) { return htole64_(x); }
uint64_t be64toh_(uint64_t x) { return htobe64_(x); }
