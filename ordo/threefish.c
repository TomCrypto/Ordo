/* Defines the Threefish cipher. */

#include <stdio.h>
#include "cipher.h"
#include "threefish.h"

/* 64-bit left and right rotation. */
#define ROL(n, r) ((n << r) | (n >> (64 - r)))
#define ROR(n, r) ((n >> r) | (n << (64 - r)))

/* Threefish key schedule. */
void Threefish_KeySchedule(void* rawKey, void* tweak, void* key)
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
		tweakWords[0] = *((unsigned long long*)tweak);
		tweakWords[1] = *((unsigned long long*)tweak + 1);
		tweakWords[2] = tweakWords[0] ^ tweakWords[1];
	}

	/* Read the key. */
	keyWords[0] = *((unsigned long long*)rawKey);
	keyWords[1] = *((unsigned long long*)rawKey + 1);
	keyWords[2] = *((unsigned long long*)rawKey + 2);
	keyWords[3] = *((unsigned long long*)rawKey + 3);
	keyWords[4] = keyWords[0] ^ keyWords[1] ^ keyWords[2] ^ keyWords[3] ^ 0x1BD11BDAA9FC1A22LL;

	/* Generate each subkey. */
	for (t = 0; t < 19; t++)
	{
		*((unsigned long long*)key + 4 * t + 0) = keyWords[(t + 0) % 5];
		*((unsigned long long*)key + 4 * t + 1) = keyWords[(t + 1) % 5] + tweakWords[(t + 0) % 3];
		*((unsigned long long*)key + 4 * t + 2) = keyWords[(t + 2) % 5] + tweakWords[(t + 1) % 3];
		*((unsigned long long*)key + 4 * t + 3) = keyWords[(t + 3) % 5] + t;
	}
}

/* Threefish permutation function. */
void Threefish_Permutation(void* block, void* key)
{
	size_t t;
	unsigned long long s;
	unsigned long long Block[4];
	unsigned long long Key[4 * 19];
	memcpy(&Block, block, THREEFISH_BLOCK);
	memcpy(&Key, key, THREEFISH_KEY);

	/* Initial key whitening. */
	Block[0] += Key[0];
	Block[1] += Key[1];
	Block[2] += Key[2];
	Block[3] += Key[3];

	/* 8 big rounds. */
	for (t = 0; t < 9; t++)
	{
		/* MIX */
		Block[0] += Block[1];
		Block[1] = ROL(Block[1], 14);
		Block[1] ^= Block[0];

		Block[2] += Block[3];
		Block[3] = ROL(Block[3], 16);
		Block[3] ^= Block[2];

		/* Permutation */
		s = Block[1];
		Block[1] = Block[3];
		Block[3] = s;

		/* MIX */
		Block[0] += Block[1];
		Block[1] = ROL(Block[1], 52);
		Block[1] ^= Block[0];

		Block[2] += Block[3];
		Block[3] = ROL(Block[3], 57);
		Block[3] ^= Block[2];

		/* Permutation */
		s = Block[1];
		Block[1] = Block[3];
		Block[3] = s;

		/* MIX */
		Block[0] += Block[1];
		Block[1] = ROL(Block[1], 23);
		Block[1] ^= Block[0];

		Block[2] += Block[3];
		Block[3] = ROL(Block[3], 40);
		Block[3] ^= Block[2];

		/* Permutation */
		s = Block[1];
		Block[1] = Block[3];
		Block[3] = s;

		/* MIX */
		Block[0] += Block[1];
		Block[1] = ROL(Block[1],  5);
		Block[1] ^= Block[0];

		Block[2] += Block[3];
		Block[3] = ROL(Block[3], 37);
		Block[3] ^= Block[2];

		/* Permutation */
		s = Block[1];
		Block[1] = Block[3];
		Block[3] = s;

		/* Subkey addition. */
		Block[0] += Key[t * 8 + 4 + 0];
		Block[1] += Key[t * 8 + 4 + 1];
		Block[2] += Key[t * 8 + 4 + 2];
		Block[3] += Key[t * 8 + 4 + 3];

		/* MIX */
		Block[0] += Block[1];
		Block[1] = ROL(Block[1], 25);
		Block[1] ^= Block[0];

		Block[2] += Block[3];
		Block[3] = ROL(Block[3], 33);
		Block[3] ^= Block[2];

		/* Permutation */
		s = Block[1];
		Block[1] = Block[3];
		Block[3] = s;

		/* MIX */
		Block[0] += Block[1];
		Block[1] = ROL(Block[1], 46);
		Block[1] ^= Block[0];

		Block[2] += Block[3];
		Block[3] = ROL(Block[3], 12);
		Block[3] ^= Block[2];

		/* Permutation */
		s = Block[1];
		Block[1] = Block[3];
		Block[3] = s;

		/* MIX */
		Block[0] += Block[1];
		Block[1] = ROL(Block[1], 58);
		Block[1] ^= Block[0];

		Block[2] += Block[3];
		Block[3] = ROL(Block[3], 22);
		Block[3] ^= Block[2];

		/* Permutation */
		s = Block[1];
		Block[1] = Block[3];
		Block[3] = s;

		/* MIX */
		Block[0] += Block[1];
		Block[1] = ROL(Block[1], 32);
		Block[1] ^= Block[0];

		Block[2] += Block[3];
		Block[3] = ROL(Block[3], 32);
		Block[3] ^= Block[2];

		/* Permutation */
		s = Block[1];
		Block[1] = Block[3];
		Block[3] = s;

		/* Subkey addition. */
		Block[0] += Key[t * 8 + 8 + 0];
		Block[1] += Key[t * 8 + 8 + 1];
		Block[2] += Key[t * 8 + 8 + 2];
		Block[3] += Key[t * 8 + 8 + 3];
	}

	/* Copy back the resulting block. */
	memcpy(block, &Block, THREEFISH_BLOCK);
}

/* Threefish inverse permutation function. */
void Threefish_Inverse(void* block, void* key)
{
	size_t t;
	unsigned long long s;
	unsigned long long Block[4];
	unsigned long long Key[4 * 19];
	memcpy(&Block, block, THREEFISH_BLOCK);
	memcpy(&Key, key, THREEFISH_KEY);

	/* 8 big rounds. */
	for (t = 9; t > 0; t--)
	{
		/* Subkey subtraction. */
		Block[0] -= Key[(t - 1) * 8 + 8 + 0];
		Block[1] -= Key[(t - 1) * 8 + 8 + 1];
		Block[2] -= Key[(t - 1) * 8 + 8 + 2];
		Block[3] -= Key[(t - 1) * 8 + 8 + 3];
		
		/* Permutation */
		s = Block[1];
		Block[1] = Block[3];
		Block[3] = s;
		
		/* Inverse MIX */
		Block[1] ^= Block[0];
		Block[1] = ROR(Block[1], 32);
		Block[0] -= Block[1];

		Block[3] ^= Block[2];
		Block[3] = ROR(Block[3], 32);
		Block[2] -= Block[3];

		/* Permutation */
		s = Block[1];
		Block[1] = Block[3];
		Block[3] = s;

		/* Inverse MIX */
		Block[1] ^= Block[0];
		Block[1] = ROR(Block[1], 58);
		Block[0] -= Block[1];

		Block[3] ^= Block[2];
		Block[3] = ROR(Block[3], 22);
		Block[2] -= Block[3];
		
		/* Permutation */
		s = Block[1];
		Block[1] = Block[3];
		Block[3] = s;

		/* Inverse MIX */
		Block[1] ^= Block[0];
		Block[1] = ROR(Block[1], 46);
		Block[0] -= Block[1];

		Block[3] ^= Block[2];
		Block[3] = ROR(Block[3], 12);
		Block[2] -= Block[3];

		/* Permutation */
		s = Block[1];
		Block[1] = Block[3];
		Block[3] = s;

		/* Inverse MIX */
		Block[1] ^= Block[0];
		Block[1] = ROR(Block[1], 25);
		Block[0] -= Block[1];

		Block[3] ^= Block[2];
		Block[3] = ROR(Block[3], 33);
		Block[2] -= Block[3];

		/* Subkey subtraction. */
		Block[0] -= Key[(t - 1) * 8 + 4 + 0];
		Block[1] -= Key[(t - 1) * 8 + 4 + 1];
		Block[2] -= Key[(t - 1) * 8 + 4 + 2];
		Block[3] -= Key[(t - 1) * 8 + 4 + 3];

		/* Permutation */
		s = Block[1];
		Block[1] = Block[3];
		Block[3] = s;

		/* Inverse MIX */
		Block[1] ^= Block[0];
		Block[1] = ROR(Block[1],  5);
		Block[0] -= Block[1];

		Block[3] ^= Block[2];
		Block[3] = ROR(Block[3], 37);
		Block[2] -= Block[3];

		/* Permutation */
		s = Block[1];
		Block[1] = Block[3];
		Block[3] = s;

		/* Inverse MIX */
		Block[1] ^= Block[0];
		Block[1] = ROR(Block[1], 23);
		Block[0] -= Block[1];

		Block[3] ^= Block[2];
		Block[3] = ROR(Block[3], 40);
		Block[2] -= Block[3];

		/* Permutation */
		s = Block[1];
		Block[1] = Block[3];
		Block[3] = s;

		/* Inverse MIX */
		Block[1] ^= Block[0];
		Block[1] = ROR(Block[1], 52);
		Block[0] -= Block[1];

		Block[3] ^= Block[2];
		Block[3] = ROR(Block[3], 57);
		Block[2] -= Block[3];

		/* Permutation */
		s = Block[1];
		Block[1] = Block[3];
		Block[3] = s;
		
		/* Inverse MIX */
		Block[1] ^= Block[0];
		Block[1] = ROR(Block[1], 14);
		Block[0] -= Block[1];

		Block[3] ^= Block[2];
		Block[3] = ROR(Block[3], 16);
		Block[2] -= Block[3];
	}

	/* Final key whitening. */
	Block[0] -= Key[0];
	Block[1] -= Key[1];
	Block[2] -= Key[2];
	Block[3] -= Key[3];

	/* Copy back the resulting block. */
	memcpy(block, &Block, THREEFISH_BLOCK);
}

/* Fills a CIPHER_PRIMITIVE struct with the correct information. */
void Threefish_SetPrimitive(CIPHER_PRIMITIVE** primitive)
{
	(*primitive) = salloc(sizeof(CIPHER_PRIMITIVE));
	(*primitive)->szRawKey = THREEFISH_RAWKEY;
	(*primitive)->szKey = THREEFISH_KEY;
	(*primitive)->szBlock = THREEFISH_BLOCK;
	(*primitive)->szTweak = THREEFISH_TWEAK;
	(*primitive)->fKeySchedule = &Threefish_KeySchedule;
	(*primitive)->fPermutation = &Threefish_Permutation;
	(*primitive)->fInverse = &Threefish_Inverse;
	(*primitive)->name = (char*)malloc(sizeof("Threefish"));
	strcpy_s((*primitive)->name, sizeof("Threefish"), "Threefish");
}