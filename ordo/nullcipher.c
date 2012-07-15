/**
 * @file NullCipher.c
 * Implements the NullCipher cipher primitive. This cipher is a test cipher which only exists as a debugging tool, and should not be used in any other context.
 *
 * The cipher itself does nothing and accepts any key size. It has a block size of 128 bits.
 *
 * @see NullCipher.h
 */

#include "primitives.h"
#include "nullcipher.h"

#define NULLCIPHER_KEY (0) // 0-bit key material
#define NULLCIPHER_BLOCK (16) // 128-bit block
#define NULLCIPHER_TWEAK 0 // no tweak

int NullCipher_KeyCheck(size_t keySize)
{
	/* All key sizes are permitted for this cipher. */
	return 1;
}

/* NullCipher key schedule. */
int NullCipher_KeySchedule(void* rawKey, size_t len, void* tweak, void* key)
{
}

/* NullCipher forward permutation function. */
void NullCipher_Forward(void* block, void* key)
{

}

/* NullCipher inverse permutation function. */
void NullCipher_Inverse(void* block, void* key)
{

}

/* Fills a CIPHER_PRIMITIVE struct with the correct information. */
void NullCipher_SetPrimitive(CIPHER_PRIMITIVE** primitive)
{
	(*primitive) = malloc(sizeof(CIPHER_PRIMITIVE));
	(*primitive)->szKey = NULLCIPHER_KEY;
	(*primitive)->szBlock = NULLCIPHER_BLOCK;
	(*primitive)->szTweak = NULLCIPHER_TWEAK;
	(*primitive)->fKeyCheck = &NullCipher_KeyCheck;
	(*primitive)->fKeySchedule = &NullCipher_KeySchedule;
	(*primitive)->fForward = &NullCipher_Forward;
	(*primitive)->fInverse = &NullCipher_Inverse;
	(*primitive)->name = "NullCipher";
}
