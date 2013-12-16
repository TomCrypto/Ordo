#ifndef ORDO_OS_RANDOM_H
#define ORDO_OS_RANDOM_H

#include "ordo/internal/api.h"

/*! @cond */
#include <stdlib.h>
/*! @endcond */

/******************************************************************************/

/*!
 * @file os_random.h
 * @brief OS-provided CSPRNG module.
 *
 * Exposes the OS CSPRNG (Cryptographically Secure PseudoRandom Number
 * Generator) interface, which is basically a cross-platform wrapper to
 * the OS-provided entropy pool.
 *
 * \b Linux: Reads from \c /dev/urandom.
 *
 * \b Windows: Acquires a CSP token and calls CryptGenRandom.
 *
 * @todo Implement ordo_random for other platforms and add proper error
 *       handling for Windows.
*/

#ifdef __cplusplus
extern "C" {
#endif

/*! Generates cryptographically secure pseudorandom numbers.
 *  @param out The buffer in which to write the pseudorandom bytes.
 *  @param len The number of bytes to generate and to write to the buffer.
 *  @return Returns \c #ORDO_SUCCESS on success, or an error code.
 *  @remarks This function uses the CSPRNG provided by your operating system.
 *  @remarks If the platform does not provide this feature, this function will
 *           always fail with \c #ORDO_FAIL.
*/
ORDO_API int ORDO_CALLCONV
os_random(void *out, size_t len);

#ifdef __cplusplus
}
#endif

#endif
