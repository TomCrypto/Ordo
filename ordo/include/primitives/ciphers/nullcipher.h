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

int NullCipher_KeyCheck(size_t keySize);

void NullCipher_KeySchedule(void* rawKey, size_t len, void* tweak, void* key, void* params);

void NullCipher_Forward(void* block, void* key);

void NullCipher_Inverse(void* block, void* key);

void NullCipher_SetPrimitive(CIPHER_PRIMITIVE* primitive);

#endif
