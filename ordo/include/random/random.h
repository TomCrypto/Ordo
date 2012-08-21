#ifndef random_h
#define random_h

/**
 * @file random.h
 * Exposes the Ordo CSPRNG (Cryptographically Secure PseudoRandom Number Generator) interface.
 *
 * @see random.c
 */

#include <common/ordotypes.h>

/*! Generates cryptographic-grade pseudorandom numbers.
  \param buffer Points to the buffer in which to write the pseudorandom stream.
  \param size The number of bytes to generate and to write to the buffer.
  \return Returns 0 on success, and returns an error code on failure.
  \remark This function uses the underlying CSPRNG provided by your operating system. */
int ordoRandom(unsigned char* buffer, size_t size);

#endif
