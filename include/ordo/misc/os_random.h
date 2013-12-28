//===-- misc/os_random.h -------------------------------*- PUBLIC -*- H -*-===//
///
/// @file
/// @brief Module
///
/// Exposes  the  OS  CSPRNG  (Cryptographically  Secure  PseudoRandom  Number
/// Generator) interface, which  is basically a cross-platform  wrapper to the
/// OS-provided entropy pool.
///
/// - \b Linux: Reads from \c /dev/urandom.
///
/// - \b Windows: Acquires a CSP token and calls CryptGenRandom.
///
//===----------------------------------------------------------------------===//

#ifndef ORDO_OS_RANDOM_H
#define ORDO_OS_RANDOM_H

/// @cond
#include "ordo/common/interface.h"
/// @endcond

#ifdef __cplusplus
extern "C" {
#endif

//===----------------------------------------------------------------------===//

/// Generates cryptographically secure pseudorandom numbers.
///
/// @param [out]    out            The destination buffer.
/// @param [in]     len            The number of bytes to generate.
///
/// @returns \c #ORDO_SUCCESS on success, else an error code.
///
/// @remarks This function uses the CSPRNG provided by your operating system.
///
/// @remarks If the platform does not provide this feature, this function will
///          always fail with the \c #ORDO_FAIL error message, and any data in
///          the buffer should be discarded as indeterminate.
ORDO_PUBLIC
int os_random(void *out, size_t len);

//===----------------------------------------------------------------------===//

#ifdef __cplusplus
}
#endif

#endif
