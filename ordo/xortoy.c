/**
 * @file XORToy.c
 * Implements the XORToy cipher primitive. This cipher is a test cipher which only exists as a debugging tool, and should not be used in any other context.
 *
 * The cipher has a block size of 128 bits, and accepts any key size multiple of 7 bytes (including zero). It performs a simple key-independent XOR of each
 * block byte with the byte 0x5A (as such, this cipher's permutation and inverse permutation are identical)
 *
 * @see XORToy.h
 */

#include "primitives.h"
#include "xortoy.h"

bool XORTOY_KeyCheck(size_t keySize)
{
	/* The key size must be a multiple of 7 (this is for testing, the cipher doesn't even use the key) */
	return (keySize % 7 == 0);
}

/* XORToy key schedule. */
bool XORToy_KeySchedule(void* rawKey, size_t len, void* tweak, void* key)
{
	return true;
}

/* XORToy permutation function. */
void XORToy_Forward(void* block, void* key)
{
	size_t t;
	for (t = 0; t < XORTOY_BLOCK; t++)
	{
		*((size_t*)((char*)block + t)) ^= 0x5A;
	}
}

/* XORToy inverse permutation function. */
void XORToy_Inverse(void* block, void* key)
{
	/* The inverse permutation happens to be the same as the forward permutation. */
	XORToy_Forward(block, key);
}

/* Fills a CIPHER_PRIMITIVE struct with the correct information. */
void XORToy_SetPrimitive(CIPHER_PRIMITIVE** primitive)
{
	(*primitive) = malloc(sizeof(CIPHER_PRIMITIVE));
	(*primitive)->szKey = XORTOY_KEY;
	(*primitive)->szBlock = XORTOY_BLOCK;
	(*primitive)->szTweak = XORTOY_TWEAK;
	(*primitive)->fKeyCheck = &XORTOY_KeyCheck;
	(*primitive)->fKeySchedule = &XORToy_KeySchedule;
	(*primitive)->fForward = &XORToy_Forward;
	(*primitive)->fInverse = &XORToy_Inverse;
	(*primitive)->name = "XORToy";
}