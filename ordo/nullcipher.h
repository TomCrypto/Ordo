/**
 * @file NullCipher.h
 * Contains the NullCipher cipher primitive interface.
 *
 * Header usage mode: External.
 *
 * @see NullCipher.c
 */

#ifndef nullcipher_h
#define nullcipher_h

#include "primitives.h"

int NullCipher_KeyCheck(size_t keySize);

int NullCipher_KeySchedule(void* rawKey, size_t len, void* tweak, void* key);

void NullCipher_Forward(void* block, void* key);

void NullCipher_Inverse(void* block, void* key);

void NullCipher_SetPrimitive(CIPHER_PRIMITIVE** primitive);

#endif
