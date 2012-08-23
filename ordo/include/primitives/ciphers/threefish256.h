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

/* A structure containing a Threefish subkey list. */
typedef struct THREEFISH256_SUBKEYS
{
    UINT256_64 subkey[19];
} THREEFISH256_SUBKEYS;

int Threefish256_KeyCheck(size_t keySize);

void Threefish256_KeySchedule(UINT256_64* rawKey, size_t len, UINT128_64* tweak, THREEFISH256_SUBKEYS* key, void* params);

void Threefish256_Forward(UINT256_64* block, THREEFISH256_SUBKEYS* key);

void Threefish256_Inverse(UINT256_64* block, THREEFISH256_SUBKEYS* key);

void Threefish256_SetPrimitive(CIPHER_PRIMITIVE* primitive);

#endif
