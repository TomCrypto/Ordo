//===-- endianness.c -----------------------------------*- darwin -*- C -*-===//

#include "ordo/misc/endianness.h"

/// @cond
#include "ordo/internal/implementation.h"
/// @endcond

#include <libkern/OSByteOrder.h>

//===----------------------------------------------------------------------===//

// OS-X has its own custom header, we just translate them here.

uint16_t htole16_(uint16_t x) { return OSSwapHostToLittleInt16(x); }
uint16_t htobe16_(uint16_t x) { return OSSwapHostToBigInt16(x); }
uint16_t le16toh_(uint16_t x) { return OSSwapLittleToHostInt16(x); }
uint16_t be16toh_(uint16_t x) { return OSSwapBigToHostInt16(x); }

uint32_t htole32_(uint32_t x) { return OSSwapHostToLittleInt32(x); }
uint32_t htobe32_(uint32_t x) { return OSSwapHostToBigInt32(x); }
uint32_t le32toh_(uint32_t x) { return OSSwapLittleToHostInt32(x); }
uint32_t be32toh_(uint32_t x) { return OSSwapBigToHostInt32(x); }

uint64_t htole64_(uint64_t x) { return OSSwapHostToLittleInt64(x); }
uint64_t htobe64_(uint64_t x) { return OSSwapHostToBigInt64(x); }
uint64_t le64toh_(uint64_t x) { return OSSwapLittleToHostInt64(x); }
uint64_t be64toh_(uint64_t x) { return OSSwapBigToHostInt64(x); }

