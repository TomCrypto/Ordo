#ifndef ORDO_RANDOM_H
#define ORDO_RANDOM_H

#include <stdlib.h>

/******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * @file random.h
 * @brief OS-provided CSPRNG module.
 *
 * Exposes the Ordo CSPRNG (Cryptographically Secure PseudoRandom Number
 * Generator) interface, which is basically a cross-platform wrapper to
 * the OS-provided entropy pool.
 *
 * \b Linux: Reads from /dev/urandom \n
 * \b Windows: Acquires a CSP token and calls CryptGenRandom. \n
 *
 * @todo Implement ordo_random for other platforms and add proper error
 *       handling for Windows.
*/

/*! Generates cryptographically secure pseudorandom numbers.
 @param buffer Points to the buffer in which to write the pseudorandom bytes.
 @param size The number of bytes to generate and to write to the buffer.
 @return Returns \c #ORDO_SUCCESS on success, or a negative value on failure.
 @remarks This function uses the underlying CSPRNG provided by your operating
          system.
*/
int ordo_random(unsigned char* buffer, size_t size);

#ifdef __cplusplus
}
#endif

#endif
