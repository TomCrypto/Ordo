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

/* A structure containing an RC4 state. */
typedef struct RC4STATE
{
    uint8_t s[256];
    uint8_t i;
    uint8_t j;
} RC4STATE;

/* A parameter structure. */
typedef struct RC4_PARAMS
{
    /* The number of bytes to drop. */
    size_t drop;
} RC4_PARAMS;

int RC4_KeyCheck(size_t keySize);

void RC4_KeySchedule(unsigned char* rawKey, size_t len, void* unused, RC4STATE* state, RC4_PARAMS* params);

void RC4_Permutation(void* block, void* key);

void RC4_SetPrimitive(CIPHER_PRIMITIVE* primitive);

#endif
