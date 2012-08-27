#ifndef threefish256_h
#define threefish256_h

/**
 * @file threefish256.h
 * Contains the Threefish-256 cipher primitive interface.
 *
 * Header usage mode: External.
 *
 * @see threefish256.c
 */

#include <primitives/primitives.h>

void Threefish256_Create(CIPHER_PRIMITIVE_CONTEXT* cipher);

int Threefish256_Init(CIPHER_PRIMITIVE_CONTEXT* cipher, UINT256_64* key, size_t keySize, void* params);

void Threefish256_Forward(CIPHER_PRIMITIVE_CONTEXT* cipher, UINT256_64* block, size_t len);

void Threefish256_Inverse(CIPHER_PRIMITIVE_CONTEXT* cipher, UINT256_64* block, size_t len);

void Threefish256_Free(CIPHER_PRIMITIVE_CONTEXT* cipher);

void Threefish256_SetPrimitive(CIPHER_PRIMITIVE* primitive);

#endif
