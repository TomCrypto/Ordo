/* Defines the XORToy cipher (this cipher is for API tests only and performs a key-independent XOR). */

#include "xortoy.h"

bool XORTOY_KeySizeCheck(size_t keySize)
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
void XORToy_Permutation(void* block, void* key)
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
	XORToy_Permutation(block, key);
}

/* Fills a CIPHER_PRIMITIVE struct with the correct information. */
void XORToy_SetPrimitive(CIPHER_PRIMITIVE** primitive)
{
	(*primitive) = salloc(sizeof(CIPHER_PRIMITIVE));
	(*primitive)->szKey = XORTOY_KEY;
	(*primitive)->szBlock = XORTOY_BLOCK;
	(*primitive)->szTweak = XORTOY_TWEAK;
	(*primitive)->fKeySizeCheck = &XORTOY_KeySizeCheck;
	(*primitive)->fKeySchedule = &XORToy_KeySchedule;
	(*primitive)->fPermutation = &XORToy_Permutation;
	(*primitive)->fInverse = &XORToy_Inverse;
	(*primitive)->name = "XORToy";
}