/* Defines the Threefish-256 cipher. */

#include "threefish256.h"

/* 64-bit left and right rotation. */
#define ROL(n, r) ((n << r) | (n >> (64 - r)))
#define ROR(n, r) ((n >> r) | (n << (64 - r)))

/* A 218-bit structure with two 64-bit words. */
typedef struct UINT128
{
	unsigned long long words[2];
} UINT128;

/* A 256-bit structure with four 64-bit words. */
typedef struct UINT256
{
	unsigned long long words[4];
} UINT256;

/* A structure containing a Threefish subkey list. */
typedef struct SUBKEYS
{
	UINT256 subkey[18];
} SUBKEYS;

bool Threefish256_KeySizeCheck(size_t keySize)
{
	/* Only a 256-bit key is permitted. */
	return (keySize == 32);
}

/* Threefish-256 key schedule. */
bool Threefish256_KeySchedule(UINT256* rawKey, size_t len, UINT128* tweak, SUBKEYS* key)
{
	size_t t;
	unsigned long long keyWords[5];
	unsigned long long tweakWords[3];

	/* Read the tweak (may be null). */
	if (tweak == 0)
	{
		memset(&tweakWords, 0, sizeof(tweakWords));
	}
	else
	{
		tweakWords[0] = tweak->words[0];
		tweakWords[1] = tweak->words[1];
		tweakWords[2] = tweakWords[0] ^ tweakWords[1];
	}

	/* Read the key. */
	keyWords[0] = rawKey->words[0];
	keyWords[1] = rawKey->words[1];
	keyWords[2] = rawKey->words[2];
	keyWords[3] = rawKey->words[3];
	keyWords[4] = keyWords[0] ^ keyWords[1] ^ keyWords[2] ^ keyWords[3] ^ 0x1BD11BDAA9FC1A22LL;

	/* Generate each subkey. */
	for (t = 0; t < 19; t++)
	{
		key->subkey[t].words[0] = keyWords[(t + 0) %  5];
		key->subkey[t].words[1] = keyWords[(t + 1) %  5] + tweakWords[(t + 0) % 3];
		key->subkey[t].words[2] = keyWords[(t + 2) %  5] + tweakWords[(t + 1) % 3];
		key->subkey[t].words[3] = keyWords[(t + 3) %  5] + t;
	}

	/* Return success. */
	return true;
}

/* Threefish-256 permutation function. */
void Threefish256_Permutation(UINT256* block, SUBKEYS* key)
{
	size_t t;
	unsigned long long s;

	/* Initial key whitening. */
	block->words[0] += key->subkey[0].words[0];
	block->words[1] += key->subkey[0].words[1];
	block->words[2] += key->subkey[0].words[2];
	block->words[3] += key->subkey[0].words[3];

	/* 8 big rounds. */
	for (t = 0; t < 9; t++)
	{
		/* MIX */
		block->words[0] += block->words[1];
		block->words[1] = ROL(block->words[1], 14);
		block->words[1] ^= block->words[0];

		block->words[2] += block->words[3];
		block->words[3] = ROL(block->words[3], 16);
		block->words[3] ^= block->words[2];

		/* Permutation */
		s = block->words[1];
		block->words[1] = block->words[3];
		block->words[3] = s;

		/* MIX */
		block->words[0] += block->words[1];
		block->words[1] = ROL(block->words[1], 52);
		block->words[1] ^= block->words[0];

		block->words[2] += block->words[3];
		block->words[3] = ROL(block->words[3], 57);
		block->words[3] ^= block->words[2];

		/* Permutation */
		s = block->words[1];
		block->words[1] = block->words[3];
		block->words[3] = s;

		/* MIX */
		block->words[0] += block->words[1];
		block->words[1] = ROL(block->words[1], 23);
		block->words[1] ^= block->words[0];

		block->words[2] += block->words[3];
		block->words[3] = ROL(block->words[3], 40);
		block->words[3] ^= block->words[2];

		/* Permutation */
		s = block->words[1];
		block->words[1] = block->words[3];
		block->words[3] = s;

		/* MIX */
		block->words[0] += block->words[1];
		block->words[1] = ROL(block->words[1],  5);
		block->words[1] ^= block->words[0];

		block->words[2] += block->words[3];
		block->words[3] = ROL(block->words[3], 37);
		block->words[3] ^= block->words[2];

		/* Permutation */
		s = block->words[1];
		block->words[1] = block->words[3];
		block->words[3] = s;

		/* Subkey addition. */
		block->words[0] += key->subkey[t * 2 + 1].words[0];
		block->words[1] += key->subkey[t * 2 + 1].words[1];
		block->words[2] += key->subkey[t * 2 + 1].words[2];
		block->words[3] += key->subkey[t * 2 + 1].words[3];

		/* MIX */
		block->words[0] += block->words[1];
		block->words[1] = ROL(block->words[1], 25);
		block->words[1] ^= block->words[0];

		block->words[2] += block->words[3];
		block->words[3] = ROL(block->words[3], 33);
		block->words[3] ^= block->words[2];

		/* Permutation */
		s = block->words[1];
		block->words[1] = block->words[3];
		block->words[3] = s;

		/* MIX */
		block->words[0] += block->words[1];
		block->words[1] = ROL(block->words[1], 46);
		block->words[1] ^= block->words[0];

		block->words[2] += block->words[3];
		block->words[3] = ROL(block->words[3], 12);
		block->words[3] ^= block->words[2];

		/* Permutation */
		s = block->words[1];
		block->words[1] = block->words[3];
		block->words[3] = s;

		/* MIX */
		block->words[0] += block->words[1];
		block->words[1] = ROL(block->words[1], 58);
		block->words[1] ^= block->words[0];

		block->words[2] += block->words[3];
		block->words[3] = ROL(block->words[3], 22);
		block->words[3] ^= block->words[2];

		/* Permutation */
		s = block->words[1];
		block->words[1] = block->words[3];
		block->words[3] = s;

		/* MIX */
		block->words[0] += block->words[1];
		block->words[1] = ROL(block->words[1], 32);
		block->words[1] ^= block->words[0];

		block->words[2] += block->words[3];
		block->words[3] = ROL(block->words[3], 32);
		block->words[3] ^= block->words[2];

		/* Permutation */
		s = block->words[1];
		block->words[1] = block->words[3];
		block->words[3] = s;

		/* Subkey addition. */
		block->words[0] += key->subkey[t * 2 + 2].words[0];
		block->words[1] += key->subkey[t * 2 + 2].words[1];
		block->words[2] += key->subkey[t * 2 + 2].words[2];
		block->words[3] += key->subkey[t * 2 + 2].words[3];
	}
}

/* Threefish-256 inverse permutation function. */
void Threefish256_Inverse(UINT256* block, SUBKEYS* key)
{
	size_t t;
	unsigned long long s;

	/* 8 big rounds. */
	for (t = 9; t > 0; t--)
	{
		/* Subkey subtraction. */
		block->words[0] -= key->subkey[(t - 1) * 2 + 2].words[0];
		block->words[1] -= key->subkey[(t - 1) * 2 + 2].words[1];
		block->words[2] -= key->subkey[(t - 1) * 2 + 2].words[2];
		block->words[3] -= key->subkey[(t - 1) * 2 + 2].words[3];
		
		/* Permutation */
		s = block->words[1];
		block->words[1] = block->words[3];
		block->words[3] = s;
		
		/* Inverse MIX */
		block->words[1] ^= block->words[0];
		block->words[1] = ROR(block->words[1], 32);
		block->words[0] -= block->words[1];

		block->words[3] ^= block->words[2];
		block->words[3] = ROR(block->words[3], 32);
		block->words[2] -= block->words[3];

		/* Permutation */
		s = block->words[1];
		block->words[1] = block->words[3];
		block->words[3] = s;

		/* Inverse MIX */
		block->words[1] ^= block->words[0];
		block->words[1] = ROR(block->words[1], 58);
		block->words[0] -= block->words[1];

		block->words[3] ^= block->words[2];
		block->words[3] = ROR(block->words[3], 22);
		block->words[2] -= block->words[3];
		
		/* Permutation */
		s = block->words[1];
		block->words[1] = block->words[3];
		block->words[3] = s;

		/* Inverse MIX */
		block->words[1] ^= block->words[0];
		block->words[1] = ROR(block->words[1], 46);
		block->words[0] -= block->words[1];

		block->words[3] ^= block->words[2];
		block->words[3] = ROR(block->words[3], 12);
		block->words[2] -= block->words[3];

		/* Permutation */
		s = block->words[1];
		block->words[1] = block->words[3];
		block->words[3] = s;

		/* Inverse MIX */
		block->words[1] ^= block->words[0];
		block->words[1] = ROR(block->words[1], 25);
		block->words[0] -= block->words[1];

		block->words[3] ^= block->words[2];
		block->words[3] = ROR(block->words[3], 33);
		block->words[2] -= block->words[3];

		/* Subkey subtraction. */
		block->words[0] -= key->subkey[(t - 1) * 2 + 1].words[0];
		block->words[1] -= key->subkey[(t - 1) * 2 + 1].words[1];
		block->words[2] -= key->subkey[(t - 1) * 2 + 1].words[2];
		block->words[3] -= key->subkey[(t - 1) * 2 + 1].words[3];

		/* Permutation */
		s = block->words[1];
		block->words[1] = block->words[3];
		block->words[3] = s;

		/* Inverse MIX */
		block->words[1] ^= block->words[0];
		block->words[1] = ROR(block->words[1],  5);
		block->words[0] -= block->words[1];

		block->words[3] ^= block->words[2];
		block->words[3] = ROR(block->words[3], 37);
		block->words[2] -= block->words[3];

		/* Permutation */
		s = block->words[1];
		block->words[1] = block->words[3];
		block->words[3] = s;

		/* Inverse MIX */
		block->words[1] ^= block->words[0];
		block->words[1] = ROR(block->words[1], 23);
		block->words[0] -= block->words[1];

		block->words[3] ^= block->words[2];
		block->words[3] = ROR(block->words[3], 40);
		block->words[2] -= block->words[3];

		/* Permutation */
		s = block->words[1];
		block->words[1] = block->words[3];
		block->words[3] = s;

		/* Inverse MIX */
		block->words[1] ^= block->words[0];
		block->words[1] = ROR(block->words[1], 52);
		block->words[0] -= block->words[1];

		block->words[3] ^= block->words[2];
		block->words[3] = ROR(block->words[3], 57);
		block->words[2] -= block->words[3];

		/* Permutation */
		s = block->words[1];
		block->words[1] = block->words[3];
		block->words[3] = s;
		
		/* Inverse MIX */
		block->words[1] ^= block->words[0];
		block->words[1] = ROR(block->words[1], 14);
		block->words[0] -= block->words[1];

		block->words[3] ^= block->words[2];
		block->words[3] = ROR(block->words[3], 16);
		block->words[2] -= block->words[3];
	}

	/* Final key whitening. */
	block->words[0] -= key->subkey[0].words[0];
	block->words[1] -= key->subkey[0].words[1];
	block->words[2] -= key->subkey[0].words[2];
	block->words[3] -= key->subkey[0].words[3];
}

/* Fills a CIPHER_PRIMITIVE struct with the correct information. */
void Threefish256_SetPrimitive(CIPHER_PRIMITIVE** primitive)
{
	(*primitive) = malloc(sizeof(CIPHER_PRIMITIVE));
	(*primitive)->szKey = THREEFISH256_KEY;
	(*primitive)->szBlock = THREEFISH256_BLOCK;
	(*primitive)->szTweak = THREEFISH256_TWEAK;
	(*primitive)->fKeySizeCheck = &Threefish256_KeySizeCheck;
	(*primitive)->fKeySchedule = &Threefish256_KeySchedule;
	(*primitive)->fPermutation = &Threefish256_Permutation;
	(*primitive)->fInverse = &Threefish256_Inverse;
	(*primitive)->name = "Threefish-256";
}
