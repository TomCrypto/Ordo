/**
 * @file Identity.c
 * Implements the Identity cipher primitive. This cipher is a test cipher which only exists as a debugging tool, and should not be used in any other context.
 *
 * The cipher itself does nothing and accepts any key size. It has a block size of 128 bits.
 *
 * @see Identity.h
 */

#include "primitives.h"
#include "identity.h"

bool Identity_KeyCheck(size_t keySize)
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
	(*primitive) = malloc(sizeof(CIPHER_PRIMITIVE));
	(*primitive)->szKey = IDENTITY_KEY;
	(*primitive)->szBlock = IDENTITY_BLOCK;
	(*primitive)->szTweak = IDENTITY_TWEAK;
	(*primitive)->fKeyCheck = &Identity_KeyCheck;
	(*primitive)->fKeySchedule = &Identity_KeySchedule;
	(*primitive)->fPermutation = &Identity_Permutation;
	(*primitive)->fInverse = &Identity_Inverse;
	(*primitive)->name = "Identity";
}