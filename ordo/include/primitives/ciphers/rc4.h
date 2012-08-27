#ifndef rc4_h
#define rc4_h

/**
 * @file rc4.h
 * Contains the RC4 cipher primitive interface. This is a stream cipher.
 *
 * Header usage mode: External.
 *
 * @see rc4.c
 */

#include <primitives/primitives.h>

/* A parameter structure. */
typedef struct RC4_PARAMS
{
    /* The number of bytes to drop. */
    size_t drop;
} RC4_PARAMS;

void RC4_Create(CIPHER_PRIMITIVE_CONTEXT* cipher);

int RC4_Init(CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* key, size_t keySize, RC4_PARAMS* params);

void RC4_Update(CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* block, size_t len);

void RC4_Free(CIPHER_PRIMITIVE_CONTEXT* cipher);

void RC4_SetPrimitive(CIPHER_PRIMITIVE* primitive);

#endif
