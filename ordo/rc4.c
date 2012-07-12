/**
 * @file rc4.c
 * Implements the RC4 cipher primitive.
 *
 * RC4 is a stream cipher, which has a 1-byte "block size" and a key size between 40 and 2048 bits (multiples of 8 bits only). It uses no tweak.
 *
 * @see rc4.h
 */

#include "primitives.h"
#include "rc4.h"

/* A structure containing an RC4 state. */
typedef struct RC4STATE
{
	unsigned char s[256];
	unsigned char i;
	unsigned char j;
} RC4STATE;

bool RC4_KeyCheck(size_t keySize)
{
	/* Allowed keys are 40-2048 bits long. */
	return ((keySize >= 5) && (keySize <= 256));
}

/* Swap two bytes. */
void swap(unsigned char* a, unsigned char* b)
{
	unsigned char c;
	c = *a;
	*a = *b;
	*b = c;
}

/* RC4 key schedule. */
bool RC4_KeySchedule(unsigned char* rawKey, size_t len, void* unused, RC4STATE* state)
{
	/* Loop variable. */
	size_t t;

	/* Initialize the permutation array. */
	for (t = 0; t < 256; t++)
	{
		state->s[t] = t;
	}

	/* Prepare the swap. */
	state->j = 0;
	for (t = 0; t < 256; t++)
	{
		state->j += state->s[t] + rawKey[t % len];
		swap(&state->s[t], &state->s[state->j]);
	}

	/* Reset the state pointers. */
	state->i = 0;
	state->j = 0;

	/* Return success. */
	return true;
}

/* RC4 forward permutation function. */
void RC4_Forward(unsigned char* output, RC4STATE* state)
{
	/* Update the state. */
	state->i++;
    state->j += state->s[state->i];
	swap(&state->s[state->i], &state->s[state->j]);
	*output = state->s[(state->s[state->i] + state->s[state->j]) % 256];
}

/* Fills a CIPHER_PRIMITIVE struct with the correct information. */
void RC4_SetPrimitive(CIPHER_PRIMITIVE** primitive)
{
	(*primitive) = malloc(sizeof(CIPHER_PRIMITIVE));
	(*primitive)->szKey = RC4_KEY;
	(*primitive)->szBlock = RC4_BLOCK;
	(*primitive)->szTweak = RC4_TWEAK;
	(*primitive)->fKeyCheck = &RC4_KeyCheck;
	(*primitive)->fKeySchedule = &RC4_KeySchedule;
	(*primitive)->fForward = &RC4_Forward;
	(*primitive)->fInverse = 0;
	(*primitive)->name = "RC4";
}
