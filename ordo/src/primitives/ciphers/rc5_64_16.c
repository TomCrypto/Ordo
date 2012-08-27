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

/* A structure containing RC5-64/16 key material. */
typedef struct RC5_64_16_KEY
{
    /* The subkeys, as 2(r + 1) = 34, 64-bit integers. */
    uint64_t subkey[34];
} RC5_64_16_KEY;

/* Shorthand macro for context casting. */
#define ctx(x) ((RC5_64_16_KEY*)(x->cipher))

void RC5_64_16_Create(CIPHER_PRIMITIVE_CONTEXT* cipher)
{
    /* Allocate space for the RC5-64/16 key material. */
    cipher->cipher = salloc(sizeof(RC5_64_16_KEY));
}

int RC5_64_16_Init(CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* key, size_t keySize, void* params)
{
    /* Loop and index variables. */
    size_t t, i, j, A, B, l;

    /* All key sizes between 40 and 512 bits are valid. */
    if ((keySize < 5) || (keySize > 64)) return ORDO_EKEYSIZE;

    /* Copy the raw key into a 64-bit word array of suitable size. */
    size_t c = (keySize + 7) / 8;
    uint64_t* L = salloc(c * 8);
    memset(L, 0, c * 8);
    memcpy(L, key, keySize);

    /* Initialize the subkey array. */
    ctx(cipher)->subkey[0] = P64;
    for (t = 1; t < 34; t++) ctx(cipher)->subkey[t] = ctx(cipher)->subkey[t - 1] + Q64;

    /* Calculate the maximum loop count. */
    if (c > 34) l = c; else l = 34;

    /* Mix the secret key into the subkey array. */
    i = 0; A = 0;
    j = 0; B = 0;
    for (t = 0; t < 3 * l; t++)
    {
        /* Apply mixing operation. */
        A = ctx(cipher)->subkey[i] = ROL((ctx(cipher)->subkey[i] + A + B), 3);
        B = L[j] = ROL((L[j] + A + B), ((A + B) & 63));

        /* Increment indexes. */
        i = (i + 1) % 34;
        j = (j + 1) % c;
    }

    /* Clean up sensitive information. */
    sfree(L, c * 8);

    /* Return success. */
    return ORDO_ESUCCESS;
}

void RC5_64_16_Forward(CIPHER_PRIMITIVE_CONTEXT* cipher, UINT128_64* block, size_t len)
{
    /* Loop variable. */
    size_t t;

    /* Initial key-whitening. */
    block->words[0] += ctx(cipher)->subkey[0];
    block->words[1] += ctx(cipher)->subkey[1];

    /* 16 rounds... */
    for (t = 1; t < 16; t++)
    {
        /* Apply this round. */
        block->words[0] = ROL((block->words[0] ^ block->words[1]), (block->words[1] & 63)) + ctx(cipher)->subkey[t * 2 + 0];
        block->words[1] = ROL((block->words[0] ^ block->words[1]), (block->words[0] & 63)) + ctx(cipher)->subkey[t * 2 + 1];
    }
}

void RC5_64_16_Inverse(CIPHER_PRIMITIVE_CONTEXT* cipher, UINT128_64* block, size_t len)
{
    /* Loop variable. */
    size_t t;

    /* 16 rounds backwards... */
    for (t = 16; t > 0; t--)
    {
        /* Apply the inverse round operation. */
        block->words[1] = ROR((block->words[1] - ctx(cipher)->subkey[t * 2 + 1]), (block->words[0] & 63)) ^ block->words[0];
        block->words[0] = ROR((block->words[0] - ctx(cipher)->subkey[t * 2 + 0]), (block->words[1] & 63)) ^ block->words[1];
    }

    /* Final key-whitening. */
    block->words[0] -= ctx(cipher)->subkey[0];
    block->words[1] -= ctx(cipher)->subkey[1];
}

void RC5_64_16_Free(CIPHER_PRIMITIVE_CONTEXT* cipher)
{
    /* Deallocate space for the RC5-64/16 key material. */
    sfree(cipher->cipher, sizeof(RC5_64_16_KEY));
}

/* Fills a CIPHER_PRIMITIVE struct with the correct information. */
void RC5_64_16_SetPrimitive(CIPHER_PRIMITIVE* primitive)
{
    PRIMITIVE_MAKECIPHER(primitive, RC5_64_16_BLOCK, RC5_64_16_Create, RC5_64_16_Init, RC5_64_16_Forward, RC5_64_16_Inverse, RC5_64_16_Free, "RC5-64/16");
}
