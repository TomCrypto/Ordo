#include <primitives/block_ciphers/threefish256.h>

#define THREEFISH256_BLOCK (32) /* 256-bit block */

/* 64-bit left and right rotation. */
#define ROL(n, r) (((n) << (r)) | ((n) >> (64 - (r))))
#define ROR(n, r) (((n) >> (r)) | ((n) << (64 - (r))))

/* A structure containing a Threefish subkey list. */
typedef struct THREEFISH256_SUBKEYS
{
    UINT256_64 subkey[19];
} THREEFISH256_SUBKEYS;

/* Shorthand macro for context casting. */
#define state(x) ((THREEFISH256_SUBKEYS*)(x->ctx))

BLOCK_CIPHER_CONTEXT* Threefish256_Create()
{
    /* Allocate space for the Threefish-256 key material. */
    BLOCK_CIPHER_CONTEXT* ctx = salloc(sizeof(BLOCK_CIPHER_CONTEXT));
    if (ctx)
    {
        if ((ctx->ctx = salloc(sizeof(THREEFISH256_SUBKEYS)))) return ctx;
        sfree(ctx, sizeof(BLOCK_CIPHER_CONTEXT));
    }

    /* Allocation failed. */
    return 0;
}

/* Macro for subkey generation. */
#define subkey(n, s0, s1, s2, s3, t0, t1) subkeys[n].words[0] = keyWords[s0]; \
                                          subkeys[n].words[1] = keyWords[s1] + tweakWords[t0]; \
                                          subkeys[n].words[2] = keyWords[s2] + tweakWords[t1]; \
                                          subkeys[n].words[3] = keyWords[s3] + n; \

/* This is the Threefish-256 key schedule. */
inline void Threefish256_KeySchedule(UINT256_64* key, uint64_t tweak[2], UINT256_64* subkeys)
{
    /* Some variables. */
    uint64_t tweakWords[3];
    uint64_t keyWords[5];
    /* Read the key. */
    keyWords[0] = key->words[0];
    keyWords[1] = key->words[1];
    keyWords[2] = key->words[2];
    keyWords[3] = key->words[3];

    /* Read the tweak. */
    if (tweak)
    {
        tweakWords[0] = tweak[0];
        tweakWords[1] = tweak[1];
    }
    else
    {
        tweakWords[0] = 0;
        tweakWords[1] = 0;
    }

    /* Calculate the extended key and tweak words. */
    keyWords[4] = keyWords[0] ^ keyWords[1] ^ keyWords[2] ^ keyWords[3] ^ (uint64_t)0x1BD11BDAA9FC1A22ULL;
    tweakWords[2] = tweakWords[0] ^ tweakWords[1];

    /* Generate each subkey (unrolled for performance). */
    subkey( 0, 0, 1, 2, 3, 0, 1);
    subkey( 1, 1, 2, 3, 4, 1, 2);
    subkey( 2, 2, 3, 4, 0, 2, 0);
    subkey( 3, 3, 4, 0, 1, 0, 1);
    subkey( 4, 4, 0, 1, 2, 1, 2);
    subkey( 5, 0, 1, 2, 3, 2, 0);
    subkey( 6, 1, 2, 3, 4, 0, 1);
    subkey( 7, 2, 3, 4, 0, 1, 2);
    subkey( 8, 3, 4, 0, 1, 2, 0);
    subkey( 9, 4, 0, 1, 2, 0, 1);
    subkey(10, 0, 1, 2, 3, 1, 2);
    subkey(11, 1, 2, 3, 4, 2, 0);
    subkey(12, 2, 3, 4, 0, 0, 1);
    subkey(13, 3, 4, 0, 1, 1, 2);
    subkey(14, 4, 0, 1, 2, 2, 0);
    subkey(15, 0, 1, 2, 3, 0, 1);
    subkey(16, 1, 2, 3, 4, 1, 2);
    subkey(17, 2, 3, 4, 0, 2, 0);
    subkey(18, 3, 4, 0, 1, 0, 1);
}

int Threefish256_Init(BLOCK_CIPHER_CONTEXT* ctx, UINT256_64* key, size_t keySize, THREEFISH256_PARAMS* params)
{
    /* Only a 256-bit key is permitted. */
    if (keySize != 32) return ORDO_EKEYSIZE;

    /* Perform the key schedule (if no tweak is specified, assume zero). */
    Threefish256_KeySchedule(key, (params == 0) ? 0 : params->tweak, state(ctx)->subkey);

    /* Returns success. */
    return ORDO_ESUCCESS;
}

/* This is the standalone Threefish-256 forward permutation. */
inline void Threefish256_Forward_Raw(UINT256_64* block, UINT256_64* subkeys)
{
    #if ENVIRONMENT_64
    Threefish256_Forward_ASM(block, &subkeys[0]);
    #else
    size_t t;
    uint64_t s;

    /* Initial key whitening. */
    block->words[0] += subkeys[0].words[0];
    block->words[1] += subkeys[0].words[1];
    block->words[2] += subkeys[0].words[2];
    block->words[3] += subkeys[0].words[3];

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
        block->words[0] += subkeys[t * 2 + 1].words[0];
        block->words[1] += subkeys[t * 2 + 1].words[1];
        block->words[2] += subkeys[t * 2 + 1].words[2];
        block->words[3] += subkeys[t * 2 + 1].words[3];

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
        block->words[0] += subkeys[t * 2 + 2].words[0];
        block->words[1] += subkeys[t * 2 + 2].words[1];
        block->words[2] += subkeys[t * 2 + 2].words[2];
        block->words[3] += subkeys[t * 2 + 2].words[3];
    }
    #endif
}

/* Threefish-256 forward permutation function. */
void Threefish256_Forward(BLOCK_CIPHER_CONTEXT* ctx, UINT256_64* block)
{
    Threefish256_Forward_Raw(block, state(ctx)->subkey);
}

/* This is the standalone Threefish-256 inverse permutation. */
inline void Threefish256_Inverse_Raw(UINT256_64* block, UINT256_64* subkeys)
{
    #if ENVIRONMENT_64
    Threefish256_Inverse_ASM(block, &subkeys[0]);
    #else
    size_t t;
    uint64_t s;

    /* 8 big rounds. */
    for (t = 9; t > 0; t--)
    {
        /* Subkey subtraction. */
        block->words[0] -= subkeys[(t - 1) * 2 + 2].words[0];
        block->words[1] -= subkeys[(t - 1) * 2 + 2].words[1];
        block->words[2] -= subkeys[(t - 1) * 2 + 2].words[2];
        block->words[3] -= subkeys[(t - 1) * 2 + 2].words[3];

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
        block->words[0] -= subkeys[(t - 1) * 2 + 1].words[0];
        block->words[1] -= subkeys[(t - 1) * 2 + 1].words[1];
        block->words[2] -= subkeys[(t - 1) * 2 + 1].words[2];
        block->words[3] -= subkeys[(t - 1) * 2 + 1].words[3];

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
    block->words[0] -= subkeys[0].words[0];
    block->words[1] -= subkeys[0].words[1];
    block->words[2] -= subkeys[0].words[2];
    block->words[3] -= subkeys[0].words[3];
    #endif
}

/* Threefish-256 inverse permutation function. */
void Threefish256_Inverse(BLOCK_CIPHER_CONTEXT* ctx, UINT256_64* block)
{
    Threefish256_Inverse_Raw(block, state(ctx)->subkey);
}

void Threefish256_Free(BLOCK_CIPHER_CONTEXT* ctx)
{
    /* Deallocate space for the Threefish-256 key material. */
    sfree(ctx->ctx, sizeof(THREEFISH256_SUBKEYS));
    sfree(ctx, sizeof(BLOCK_CIPHER_CONTEXT));
}

/* Fills a BLOCK_CIPHER struct with the correct information. */
void Threefish256_SetPrimitive(BLOCK_CIPHER* cipher)
{
    MAKE_BLOCK_CIPHER(cipher, THREEFISH256_BLOCK, Threefish256_Create, Threefish256_Init, Threefish256_Forward, Threefish256_Inverse, Threefish256_Free, "Threefish-256");
}
