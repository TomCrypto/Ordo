#ifndef ORDO_OS_RANDOM_H
#define ORDO_OS_RANDOM_H

#include <stdlib.h>

/******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

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
 * If the platform does not have this feature, this module will consistently
 * return \c #ORDO_FAIL.
 *
 * @todo Implement ordo_random for other platforms and add proper error
 *       handling for Windows.
*/

/*! Generates cryptographically secure pseudorandom numbers.
 @param out The buffer in which to write the pseudorandom bytes.
 @param len The number of bytes to generate and to write to the buffer.
 @return Returns \c #ORDO_SUCCESS on success, or a negative value on failure.
 @remarks This function uses the CSPRNG provided by your operating system.
 @remarks If the platform does not provide this feature, this function will
          always return \c #ORDO_FAIL.
*/
int os_random(void *out, size_t len);

#ifdef __cplusplus
}
#endif

#endif
