/* Defines the Identity cipher (this cipher is for API tests only and does nothing). */

#include "cipher.h"
#include "identity.h"

/* Identity key schedule. */
void Identity_KeySchedule(void* rawKey, void* tweak, void* key)
{
	return;
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
	(*primitive)->szRawKey = IDENTITY_RAWKEY;
	(*primitive)->szKey = IDENTITY_KEY;
	(*primitive)->szBlock = IDENTITY_BLOCK;
	(*primitive)->szTweak = IDENTITY_TWEAK;
	(*primitive)->fKeySchedule = &Identity_KeySchedule;
	(*primitive)->fPermutation = &Identity_Permutation;
	(*primitive)->fInverse = &Identity_Inverse;
	(*primitive)->name = (char*)malloc(sizeof("Identity"));
	strcpy_s((*primitive)->name, sizeof("Identity"), "Identity");
}