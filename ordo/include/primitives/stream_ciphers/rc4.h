#ifndef RC4_H
#define RC4_H

/**
 * @file rc4.h
 *
 * \brief RC4 stream cipher.
 *
 * RC4 is a stream cipher, which accepts keys between 40 and 2048 bits (in multiples of 8 bits only). It accepts a
 * parameter consisting of the number of initial keystream bytes to drop immediately after key schedule, effectively
 * implementing RC4-drop[n]. If no drop  parameter is passed, the implementation drops 2048 bytes by default.
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

STREAM_CIPHER_CONTEXT* RC4_Create();

int RC4_Init(STREAM_CIPHER_CONTEXT* ctx, unsigned char* key, size_t keySize, RC4_PARAMS* params);

void RC4_Update(STREAM_CIPHER_CONTEXT* ctx, unsigned char* buffer, size_t len);

void RC4_Free(STREAM_CIPHER_CONTEXT* ctx);

void RC4_SetPrimitive(STREAM_CIPHER* cipher);

#endif
