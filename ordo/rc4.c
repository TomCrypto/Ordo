/**
 * @file rc4.c
 * Implements the RC4 cipher primitive.
 *
 * RC4 is a stream cipher, which has a 1-byte "block size" and a key size between 40 and 2048 bits (multiples of 8 bits only). It uses no tweak.
 * Note this implementation of RC4 drops the first 2048 bytes of the keystream for security reasons, so technically this is RC4-drop[2048].
 *
 * @see rc4.h
 */

#include "primitives.h"
#include "rc4.h"

#define RC4_KEY (2064 / 8)
#define RC4_BLOCK (8 / 8) // 8-bit block
#define RC4_TWEAK 0 // no tweak

int RC4_KeyCheck(size_t keySize)
{
	/* Allowed keys are 40-2048 bits long. */
	return ((keySize >= 5) && (keySize <= 256));
}

/* Swaps two bytes. */
void swapByte(unsigned char* a, unsigned char* b)
{
	unsigned char c;
	c = *a;
	*a = *b;
	*b = c;
}

/* RC4 forward permutation function. */
void RC4_Forward(unsigned char* output, RC4STATE* state)
{
	/* Update the state. */
	state->i++;
    state->j += state->s[state->i];
	swapByte(&state->s[state->i], &state->s[state->j]);
	if (output != 0) *output = state->s[(state->s[state->i] + state->s[state->j]) % 256];
}

/* RC4 key schedule. */
void RC4_KeySchedule(unsigned char* rawKey, size_t len, void* unused, RC4STATE* state)
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
		swapByte(&state->s[t], &state->s[state->j]);
	}

	/* Reset the state pointers. */
	state->i = 0;
	state->j = 0;

	/* Throw away the first 2048 bytes. */
	for (t = 0; t < 2048; t++) RC4_Forward(0, state);
}

/* Fills a CIPHER_PRIMITIVE struct with the correct information. */
void RC4_SetPrimitive(CIPHER_PRIMITIVE* primitive)
{
    PRIMITIVE_MAKECIPHER(primitive, RC4_KEY, RC4_BLOCK, RC4_TWEAK, RC4_KeyCheck, RC4_KeySchedule, RC4_Forward, 0, "RC4");
}
