/* Defines the Identity cipher (this cipher is for API tests only and does nothing). */

#include "cipher.h"
#include "identity.h"

bool Identity_KeySizeCheck(size_t keySize)
{
	/* All key sizes are permitted for this cipher. */
	return true;
}

/* Identity key schedule. */
bool Identity_KeySchedule(void* rawKey, size_t len, void* tweak, void* key)
{
	return true;
}

/* Identity permutation function. */
void Identity_Permutation(void* block, void* key)
{
	return;
}

/* Identity inverse permutation function. */
void Identity_Inverse(void* block, void* key)
{
	return;
}

/* Fills a CIPHER_PRIMITIVE struct with the correct information. */
void Identity_SetPrimitive(CIPHER_PRIMITIVE** primitive)
{
	(*primitive) = salloc(sizeof(CIPHER_PRIMITIVE));
	(*primitive)->szKey = IDENTITY_KEY;
	(*primitive)->szBlock = IDENTITY_BLOCK;
	(*primitive)->szTweak = IDENTITY_TWEAK;
	(*primitive)->fKeySizeCheck = &Identity_KeySizeCheck;
	(*primitive)->fKeySchedule = &Identity_KeySchedule;
	(*primitive)->fPermutation = &Identity_Permutation;
	(*primitive)->fInverse = &Identity_Inverse;
	(*primitive)->name = "Identity";
}