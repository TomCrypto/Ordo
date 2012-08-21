/**
 * @file rc5_64_16.c
 * Implements the RC5-64/16 cipher primitive.
 *
 * RC5-64/16 has a 128-bit block size, a 128-bit key size, and no tweak.
 *
 * @see rc5_64_16.h
 */

#include <primitives/primitives.h>
#include <primitives/ciphers/rc5_64_16.h>

#define RC5_64_16_KEY_SIZE (sizeof(RC5_64_16_KEY)) // 2176-bit extended key (34 subkeys x 64 bits)
#define RC5_64_16_BLOCK (16) // 128-bit block
#define RC5_64_16_TWEAK (0) // 0-bit tweak

/* 64-bit left and right rotation. */
#define ROL(n, r) ((n << r) | (n >> (64 - r)))
#define ROR(n, r) ((n >> r) | (n << (64 - r)))

/* Magic key schedule constants. */
#define P64 0xb7e151628aed2a6b
#define Q64 0x9e3779b97f4a7c15

int RC5_64_16_KeyCheck(size_t keySize)
{
    /* All key sizes between 40 and 512 bits are valid. */
    return ((keySize >= 5) && (keySize <= 64));
}

/* RC5-64/16 key schedule. */
void RC5_64_16_KeySchedule(unsigned char* rawKey, size_t len, void* tweak, RC5_64_16_KEY* key, RC5_64_16_PARAMS* params)
{
    /* Loop and index variables. */
    size_t t, i, j, A, B, l;

    /* Save the number of rounds to use (default to 16). */
    key->rounds = (params == 0) ? 16 : params->rounds;

    /* Copy the raw key into a 64-bit word array of suitable size. */
    size_t c = (len + 7) / 8;
    unsigned long long* L = salloc(c * 8);
    memset(L, 0, c * 8);
    memcpy(L, rawKey, len);

    /* Initialize the subkey array. */
    key->subkey[0] = P64;
    for (t = 1; t < 2 * (key->rounds + 1); t++) key->subkey[t] = key->subkey[t - 1] + Q64;

    /* Calculate the maximum loop count. */
    if (c > 2 * (key->rounds + 1)) l = c; else l = 2 * (key->rounds + 1);

    /* Mix the secret key into the subkey array. */
    i = 0; A = 0;
    j = 0; B = 0;
    for (t = 0; t < 3 * l; t++)
    {
        /* Apply mixing operation. */
        A = key->subkey[i] = ROL((key->subkey[i] + A + B), 3);
        B = L[j] = ROL((L[j] + A + B), ((A + B) & 63));

        /* Increment indexes. */
        i = (i + 1) % (2 * (key->rounds + 1));
        j = (j + 1) % c;
    }

    /* Clean up sensitive information. */
    sfree(L, c * 8);
}

/* RC5-64/16 forward permutation function. */
void RC5_64_16_Forward(UINT128* block, RC5_64_16_KEY* key)
{
    /* Loop variable. */
    size_t t;

    /* Initial key-whitening. */
    block->words[0] += key->subkey[0];
    block->words[1] += key->subkey[1];

    /* 16 rounds... */
    for (t = 1; t < key->rounds; t++)
    {
        /* Apply this round. */
        block->words[0] = ROL((block->words[0] ^ block->words[1]), (block->words[1] & 63)) + key->subkey[t * 2 + 0];
        block->words[1] = ROL((block->words[0] ^ block->words[1]), (block->words[0] & 63)) + key->subkey[t * 2 + 1];
    }
}

/* RC5-64/16 inverse permutation function. */
void RC5_64_16_Inverse(UINT128* block, RC5_64_16_KEY* key)
{
    /* Loop variable. */
    size_t t;

    /* 16 rounds backwards... */
    for (t = key->rounds; t > 0; t--)
    {
        /* Apply the inverse round operation. */
        block->words[1] = ROR((block->words[1] - key->subkey[t * 2 + 1]), (block->words[0] & 63)) ^ block->words[0];
        block->words[0] = ROR((block->words[0] - key->subkey[t * 2 + 0]), (block->words[1] & 63)) ^ block->words[1];
    }

    /* Final key-whitening. */
    block->words[0] -= key->subkey[0];
    block->words[1] -= key->subkey[1];
}

/* Fills a CIPHER_PRIMITIVE struct with the correct information. */
void RC5_64_16_SetPrimitive(CIPHER_PRIMITIVE* primitive)
{
    PRIMITIVE_MAKECIPHER(primitive, RC5_64_16_KEY_SIZE, RC5_64_16_BLOCK, RC5_64_16_TWEAK, RC5_64_16_KeyCheck, RC5_64_16_KeySchedule, RC5_64_16_Forward, RC5_64_16_Inverse, "RC5-64/16");
}
