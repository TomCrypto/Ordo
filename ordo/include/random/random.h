#ifndef RANDOM_H
#define RANDOM_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file random.h
 *
 * \brief Cryptographically secure pseudorandom number generation.
 *
 * Exposes the Ordo CSPRNG (Cryptographically Secure PseudoRandom Number Generator) interface, which is basically a
 * cross-platform wrapper to the OS-provided entropy pool.
 *
 * Linux: Reads from /dev/urandom \n
 * Windows: Acquires a CSP token and calls CryptGenRandom. \n
 *
 * \todo Implement ordoRandom for other platforms and add proper error handling for Windows.
 *
 * @see random.c
 */

#include <common/ordotypes.h>

/*! Generates cryptographic-grade pseudorandom numbers.
  \param buffer Points to the buffer in which to write the pseudorandom stream.
  \param size The number of bytes to generate and to write to the buffer.
  \return Returns \c ORDO_ESUCCESS on success, and returns an error code on failure.
  \remark This function uses the underlying CSPRNG provided by your operating system. */
int ordoRandom(unsigned char* buffer, size_t size);

#ifdef __cplusplus
}
#endif

#endif
