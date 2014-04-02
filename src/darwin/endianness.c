/*===-- endianness.c -----------------------------------*- darwin -*- C -*-===*/

#include "ordo/misc/endianness.h"

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

#include <libkern/OSByteOrder.h>

/*===----------------------------------------------------------------------===*/

/* OS-X has its own custom header, we just translate them here. */

uint16_t tole16(uint16_t x) { return OSSwapHostToLittleInt16(x); }
uint16_t tobe16(uint16_t x) { return OSSwapHostToBigInt16(x);    }
uint16_t fmle16(uint16_t x) { return OSSwapLittleToHostInt16(x); }
uint16_t fmbe16(uint16_t x) { return OSSwapBigToHostInt16(x);    }

uint32_t tole32(uint32_t x) { return OSSwapHostToLittleInt32(x); }
uint32_t tobe32(uint32_t x) { return OSSwapHostToBigInt32(x);    }
uint32_t fmle32(uint32_t x) { return OSSwapLittleToHostInt32(x); }
uint32_t fmbe32(uint32_t x) { return OSSwapBigToHostInt32(x);    }

uint64_t tole64(uint64_t x) { return OSSwapHostToLittleInt64(x); }
uint64_t tobe64(uint64_t x) { return OSSwapHostToBigInt64(x);    }
uint64_t fmle64(uint64_t x) { return OSSwapLittleToHostInt64(x); }
uint64_t fmbe64(uint64_t x) { return OSSwapBigToHostInt64(x);    }

