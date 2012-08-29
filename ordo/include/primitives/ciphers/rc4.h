#ifndef rc4_h
#define rc4_h

/**
 * @file rc4.h
 *
 * \brief RC4 stream cipher interface.
 *
 * Contains the RC4 cipher primitive interface.
 *
 * RC4 is a stream cipher, which has no block size and accepts keys between 40 and 2048 bits (in multiples of 8 bits only). It accepts a parameter
 * consisting of the number of initial keystream bytes to drop immediately after key schedule, effectively implementing RC4-drop[n]. If no drop
 * parameter is passed, the implementation drops 2048 bytes by default.
 *
 * \todo Better ABI translation for Windows assembler implementation (right now it's a brute force push/pop/swap to explicitly translate parameter passing).
 *
 * @see rc4.c
 */

#include <primitives/primitives.h>

/*! The parameter structure for RC4. */
typedef struct RC4_PARAMS
{
    /*! The number of keystream bytes to drop before encryption. */
    size_t drop;
} RC4_PARAMS;

/*! This function allocates the RC4 state in the low-level context. */
void RC4_Create(CIPHER_PRIMITIVE_CONTEXT* cipher);

/*! This function performs the key schedule of the RC4 state with the passed key, and drops bytes according to the params structure. */
int RC4_Init(CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* key, size_t keySize, RC4_PARAMS* params);

/*! This function encrypts or decrypts a buffer and updates the RC4 state. This function is transitive. */
void RC4_Update(CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* block, size_t len);

/*! This function deallocates the RC4 state in the low-level cipher primitive context. */
void RC4_Free(CIPHER_PRIMITIVE_CONTEXT* cipher);

/*! This function will populate a cipher primitive object with the RC4 details. */
void RC4_SetPrimitive(CIPHER_PRIMITIVE* primitive);

#endif
