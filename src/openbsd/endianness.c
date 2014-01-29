//===-- endianness.c ----------------------------------*- openbsd -*- C -*-===//

#include "ordo/misc/endianness.h"

/// @cond
#include "ordo/internal/implementation.h"
/// @endcond

#include <sys/types.h>
#include <sys/endian.h>

//===----------------------------------------------------------------------===//

// For most BSD's the header is actually sys/endian.h, and macros are slightly
// different (they always have the word size at the end, not after "le"/"be").

uint16_t htole16_(uint16_t x) { return htole16(x); }
uint16_t htobe16_(uint16_t x) { return htobe16(x); }
uint16_t le16toh_(uint16_t x) { return letoh16(x); }
uint16_t be16toh_(uint16_t x) { return betoh16(x); }

uint32_t htole32_(uint32_t x) { return htole32(x); }
uint32_t htobe32_(uint32_t x) { return htobe32(x); }
uint32_t le32toh_(uint32_t x) { return letoh32(x); }
uint32_t be32toh_(uint32_t x) { return betoh32(x); }

uint64_t htole64_(uint64_t x) { return htole64(x); }
uint64_t htobe64_(uint64_t x) { return htobe64(x); }
uint64_t le64toh_(uint64_t x) { return letoh64(x); }
uint64_t be64toh_(uint64_t x) { return betoh64(x); }

