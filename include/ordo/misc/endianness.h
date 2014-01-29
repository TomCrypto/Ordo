//===-- misc/endianness.h -------------------------------*- PUBLIC-*- H -*-===//
///
/// @file
/// @brief \b Utility
///
/// This header provides endianness functionality. You may use it freely as it
/// has a stable API and is public. Only supports little/big endian for now.
///
//===----------------------------------------------------------------------===//

#ifndef ORDO_SYS_H
#define ORDO_SYS_H

/// @cond
#include "ordo/common/interface.h"
/// @endcond

//===----------------------------------------------------------------------===//

ORDO_PUBLIC uint16_t htole16_(uint16_t x);
ORDO_PUBLIC uint16_t htobe16_(uint16_t x);
ORDO_PUBLIC uint16_t le16toh_(uint16_t x);
ORDO_PUBLIC uint16_t be16toh_(uint16_t x);

ORDO_PUBLIC uint32_t htole32_(uint32_t x);
ORDO_PUBLIC uint32_t htobe32_(uint32_t x);
ORDO_PUBLIC uint32_t le32toh_(uint32_t x);
ORDO_PUBLIC uint32_t be32toh_(uint32_t x);

ORDO_PUBLIC uint64_t htole64_(uint64_t x);
ORDO_PUBLIC uint64_t htobe64_(uint64_t x);
ORDO_PUBLIC uint64_t le64toh_(uint64_t x);
ORDO_PUBLIC uint64_t be64toh_(uint64_t x);

//===----------------------------------------------------------------------===//
