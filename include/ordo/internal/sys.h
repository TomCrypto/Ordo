//===-- internal/sys.h --------------------------------*- INTERNAL-*- H -*-===//
///
/// @file
/// @internal
/// @brief \b Internal, Utility
///
/// This header provides system-dependent functionality such as endianness
///
//===----------------------------------------------------------------------===//

#ifndef ORDO_SYS_H
#define ORDO_SYS_H

/// @cond
#include "ordo/common/interface.h"
/// @endcond

//===----------------------------------------------------------------------===//

ORDO_HIDDEN uint16_t htole16_(uint16_t x);
ORDO_HIDDEN uint16_t htobe16_(uint16_t x);
ORDO_HIDDEN uint16_t le16toh_(uint16_t x);
ORDO_HIDDEN uint16_t be16toh_(uint16_t x);

ORDO_HIDDEN uint32_t htole32_(uint32_t x);
ORDO_HIDDEN uint32_t htobe32_(uint32_t x);
ORDO_HIDDEN uint32_t le32toh_(uint32_t x);
ORDO_HIDDEN uint32_t be32toh_(uint32_t x);

ORDO_HIDDEN uint64_t htole64_(uint64_t x);
ORDO_HIDDEN uint64_t htobe64_(uint64_t x);
ORDO_HIDDEN uint64_t le64toh_(uint64_t x);
ORDO_HIDDEN uint64_t be64toh_(uint64_t x);

//===----------------------------------------------------------------------===//

#endif
