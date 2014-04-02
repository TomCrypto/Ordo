/*===-- endianness.c ----------------------------------*- openbsd -*- C -*-===*/

#include "ordo/misc/endianness.h"

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

#include <sys/types.h>
#include <sys/endian.h>

/*===----------------------------------------------------------------------===*/

/* For most BSD's the header is actually sys/endian.h, and macros are slightly
 * different (they always have the word size at the end, not after "le"/"be").
*/

uint16_t tole16(uint16_t x) { return htole16(x); }
uint16_t tobe16(uint16_t x) { return htobe16(x); }
uint16_t fmle16(uint16_t x) { return letoh16(x); }
uint16_t fmbe16(uint16_t x) { return betoh16(x); }

uint32_t tole32(uint32_t x) { return htole32(x); }
uint32_t tobe32(uint32_t x) { return htobe32(x); }
uint32_t fmle32(uint32_t x) { return letoh32(x); }
uint32_t fmbe32(uint32_t x) { return betoh32(x); }

uint64_t tole64(uint64_t x) { return htole64(x); }
uint64_t tobe64(uint64_t x) { return htobe64(x); }
uint64_t fmle64(uint64_t x) { return letoh64(x); }
uint64_t fmbe64(uint64_t x) { return betoh64(x); }

