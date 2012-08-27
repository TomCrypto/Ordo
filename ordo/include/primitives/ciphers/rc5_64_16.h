#ifndef rc5_64_16_h
#define rc5_64_16_h

/**
 * @file rc5_64_16.h
 * Contains the RC5-64/16 (= 64-bit word size, 16 rounds) cipher primitive interface. This is a block cipher.
 *
 * Header usage mode: External.
 *
 * @see rc5_64_16_16.c
 */

#include <primitives/primitives.h>

void RC5_64_16_Create(CIPHER_PRIMITIVE_CONTEXT* cipher);

int RC5_64_16_Init(CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* key, size_t keySize, void* params);

void RC5_64_16_Forward(CIPHER_PRIMITIVE_CONTEXT* cipher, UINT128_64* block, size_t len);

void RC5_64_16_Inverse(CIPHER_PRIMITIVE_CONTEXT* cipher, UINT128_64* block, size_t len);

void RC5_64_16_Free(CIPHER_PRIMITIVE_CONTEXT* cipher);

void RC5_64_16_SetPrimitive(CIPHER_PRIMITIVE* primitive);

#endif
