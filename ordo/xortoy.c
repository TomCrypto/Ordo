/* Defines the XORToy cipher (this cipher is for API tests only and performs a key-independent XOR). */

#include "cipher.h"
#include "xortoy.h"

/* XORToy key schedule. */
void XORToy_KeySchedule(void* rawKey, void* tweak, void* key)
{
	return;
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
void XORToy_SetPrimitive(CIPHER_PRIMITIVE* primitive)
{
	primitive->szRawKey = XORTOY_RAWKEY;
	primitive->szKey = XORTOY_KEY;
	primitive->szBlock = XORTOY_BLOCK;
	primitive->szTweak = XORTOY_TWEAK;
	primitive->fKeySchedule = &XORToy_KeySchedule;
	primitive->fPermutation = &XORToy_Permutation;
	primitive->fInverse = &XORToy_Inverse;
	primitive->name = (char*)malloc(sizeof("XORToy"));
	strcpy_s(primitive->name, sizeof("XORToy"), "XORToy");
}