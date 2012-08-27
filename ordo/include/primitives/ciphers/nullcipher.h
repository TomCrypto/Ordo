#ifndef nullcipher_h
#define nullcipher_h

/**
 * @file nullcipher.h
 * Contains the NullCipher cipher primitive interface.
 *
 * Header usage mode: External.
 *
 * @see nullcipher.c
 */

#include <primitives/primitives.h>

void NullCipher_Create(CIPHER_PRIMITIVE_CONTEXT* cipher);

int NullCipher_Init(CIPHER_PRIMITIVE_CONTEXT* cipher, void* key, size_t keySize, void* params);

void NullCipher_Forward(CIPHER_PRIMITIVE_CONTEXT* cipher, void* block);

void NullCipher_Inverse(CIPHER_PRIMITIVE_CONTEXT* cipher, void* block);

void NullCipher_Free(CIPHER_PRIMITIVE_CONTEXT* cipher);

void NullCipher_SetPrimitive(CIPHER_PRIMITIVE* primitive);

#endif
