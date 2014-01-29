//===-- misc/endianness.h -------------------------------*- PUBLIC-*- H -*-===//
///
/// @file
/// @brief Utility
///
/// This header provides endianness functionality. You may use it freely as it
/// has a stable API and is public. Only supports little/big endian for now.
///
/// The functions in this header are not prefixed, be wary of name clashes.
///
//===----------------------------------------------------------------------===//

#ifndef ORDO_ENDIANNESS_H
#define ORDO_ENDIANNESS_H

/// @cond
#include "ordo/common/interface.h"
/// @endcond

#ifdef __cplusplus
extern "C" {
#endif

//===----------------------------------------------------------------------===//

// tole16  ==  host --> little-endian (16 bits)
// fmbe32  ==  host <-- big-endian    (32 bits)
// etc.

ORDO_PUBLIC uint16_t tole16(uint16_t x);
ORDO_PUBLIC uint16_t tobe16(uint16_t x);
ORDO_PUBLIC uint16_t fmle16(uint16_t x);
ORDO_PUBLIC uint16_t fmbe16(uint16_t x);

ORDO_PUBLIC uint32_t tole32(uint32_t x);
ORDO_PUBLIC uint32_t tobe32(uint32_t x);
ORDO_PUBLIC uint32_t fmle32(uint32_t x);
ORDO_PUBLIC uint32_t fmbe32(uint32_t x);

ORDO_PUBLIC uint64_t tole64(uint64_t x);
ORDO_PUBLIC uint64_t tobe64(uint64_t x);
ORDO_PUBLIC uint64_t fmle64(uint64_t x);
ORDO_PUBLIC uint64_t fmbe64(uint64_t x);

//===----------------------------------------------------------------------===//

#ifdef __cplusplus
}
#endif

#endif
