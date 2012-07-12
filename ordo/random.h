/**
 * @file random.h
 * Exposes the Ordo CSPRNG (Cryptographically Secure PseudoRandom Number Generator) interface.
 * 
 * Header usage mode: External.
 *
 * @see random.c
 */

/* Standard includes. */
#include <stdlib.h>

/*! Generates cryptographic-grade pseudorandom numbers.
  \param buffer Points to the buffer in which to write the pseudorandom stream.
  \param size The number of bytes to generate and to write to the buffer.
  \remark This function uses the underlying CSPRNG provided by your operating system. */
void random(void* buffer, size_t size);