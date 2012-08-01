/**
 * @file rc4.h
 * Contains the RC4 cipher primitive interface. This is a stream cipher.
 *
 * Header usage mode: External.
 *
 * @see rc4.c
 */

#ifndef rc4_h
#define rc4_h

#include "primitives.h"

/* A structure containing an RC4 state. */
typedef struct RC4STATE
{
	unsigned char s[256];
	unsigned char i;
	unsigned char j;
} RC4STATE;

int RC4_KeyCheck(size_t keySize);

void RC4_KeySchedule(unsigned char* rawKey, size_t len, void* unused, RC4STATE* state);

void RC4_Permutation(void* block, void* key);

void RC4_SetPrimitive(CIPHER_PRIMITIVE* primitive);

#endif
