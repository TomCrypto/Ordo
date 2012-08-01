/**
 * @file threefish256.h
 * Contains the Threefish-256 cipher primitive interface.
 *
 * Header usage mode: External.
 *
 * @see threefish256.c
 */

#ifndef threefish256_h
#define threefish256_h

#include "primitives.h"

/* A 128-bit structure with two 64-bit words. */
typedef struct UINT128
{
	unsigned long long words[2];
} UINT128;

/* A 256-bit structure with four 64-bit words. */
typedef struct UINT256
{
	unsigned long long words[4];
} UINT256;

/* A structure containing a Threefish subkey list. */
typedef struct SUBKEYS
{
	UINT256 subkey[18];
} SUBKEYS;

int Threefish256_KeyCheck(size_t keySize);

void Threefish256_KeySchedule(UINT256* rawKey, size_t len, UINT128* tweak, SUBKEYS* key);

void Threefish256_Forward(UINT256* block, SUBKEYS* key);

void Threefish256_Inverse(UINT256* block, SUBKEYS* key);

void Threefish256_SetPrimitive(CIPHER_PRIMITIVE* primitive);

#endif
