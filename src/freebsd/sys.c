//===-- sys.c -----------------------------------*- [net/free]bsd -*- C -*-===//

#include "ordo/internal/sys.h"

/// @cond
#include "ordo/internal/implementation.h"
/// @endcond

#include <sys/types.h>
#include <sys/endian.h>

//===----------------------------------------------------------------------===//

// For some reason Free/NetBSD use the BSD header with the Linux notation.

uint16_t htole16_(uint16_t x) { return htole16(x); }
uint16_t htobe16_(uint16_t x) { return htobe16(x); }
uint16_t le16toh_(uint16_t x) { return le16toh(x); }
uint16_t be16toh_(uint16_t x) { return be16toh(x); }

uint32_t htole32_(uint32_t x) { return htole32(x); }
uint32_t htobe32_(uint32_t x) { return htobe32(x); }
uint32_t le32toh_(uint32_t x) { return le32toh(x); }
uint32_t be32toh_(uint32_t x) { return be32toh(x); }

uint64_t htole64_(uint64_t x) { return htole64(x); }
uint64_t htobe64_(uint64_t x) { return htobe64(x); }
uint64_t le64toh_(uint64_t x) { return le64toh(x); }
uint64_t be64toh_(uint64_t x) { return be64toh(x); }

