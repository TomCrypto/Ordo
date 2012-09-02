#ifndef rc4_h
#define rc4_h

/**
 * @file rc4.h
 *
 * \brief RC4 stream cipher interface.
 *
 * RC4 is a stream cipher, which has no block size and accepts keys between 40 and 2048 bits (in multiples of 8 bits only). It accepts a parameter
 * consisting of the number of initial keystream bytes to drop immediately after key schedule, effectively implementing RC4-drop[n]. If no drop
 * parameter is passed, the implementation drops 2048 bytes by default.
 *
 * By virtue of being a stream cipher, it is only compatible with the STREAM encryption mode of operation.
 *
 * \todo Better ABI translation for Windows assembler implementation (right now it's a brute force push/pop/swap to explicitly translate parameter passing).
 *
 * @see rc4.c
 */

#include <primitives/primitives.h>

/*! \brief RC4 cipher parameters.
 *
 * The parameter structure for RC4. */
typedef struct RC4_PARAMS
{
    /*! The number of keystream bytes to drop prior to encryption. */
    size_t drop;
} RC4_PARAMS;

void RC4_Create(CIPHER_PRIMITIVE_CONTEXT* cipher);

int RC4_Init(CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* key, size_t keySize, RC4_PARAMS* params);

void RC4_Update(CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* block, size_t len);

void RC4_Free(CIPHER_PRIMITIVE_CONTEXT* cipher);

void RC4_SetPrimitive(CIPHER_PRIMITIVE* primitive);

#endif
