/*===-- endianness.c ----------------------------*- [net/free]bsd -*- C -*-===*/

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

#include "ordo/misc/endianness.h"

#include <sys/types.h>
#include <sys/endian.h>

/*===----------------------------------------------------------------------===*/

/* For some reason Free/NetBSD use the BSD header with the Linux notation. */

uint16_t tole16(uint16_t x) { return htole16(x); }
uint16_t tobe16(uint16_t x) { return htobe16(x); }
uint16_t fmle16(uint16_t x) { return le16toh(x); }
uint16_t fmbe16(uint16_t x) { return be16toh(x); }

uint32_t tole32(uint32_t x) { return htole32(x); }
uint32_t tobe32(uint32_t x) { return htobe32(x); }
uint32_t fmle32(uint32_t x) { return le32toh(x); }
uint32_t fmbe32(uint32_t x) { return be32toh(x); }

uint64_t tole64(uint64_t x) { return htole64(x); }
uint64_t tobe64(uint64_t x) { return htobe64(x); }
uint64_t fmle64(uint64_t x) { return le64toh(x); }
uint64_t fmbe64(uint64_t x) { return be64toh(x); }

