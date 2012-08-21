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

/* A structure containing RC5_64/16 key material. */
typedef struct RC5_64_16_KEY
{
    /* The subkeys, as 2(r + 1) = 34, 64-bit integers. */
    unsigned long long subkey[34];
    /* The number of rounds. */
    size_t rounds;
} RC5_64_16_KEY;

/* A parameter structure. */
typedef struct RC5_64_16_PARAMS
{
    /* The number of rounds to use. */
    size_t rounds;
} RC5_64_16_PARAMS;

int RC5_64_16_KeyCheck(size_t keySize);

void RC5_64_16_KeySchedule(unsigned char* rawKey, size_t len, void* tweak, RC5_64_16_KEY* key, RC5_64_16_PARAMS* params);

void RC5_64_16_Forward(UINT128* block, RC5_64_16_KEY* key);

void RC5_64_16_Inverse(UINT128* block, RC5_64_16_KEY* key);

void RC5_64_16_SetPrimitive(CIPHER_PRIMITIVE* primitive);

#endif
