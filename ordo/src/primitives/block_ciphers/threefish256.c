#include <primitives/primitives.h>
#include <primitives/block_ciphers/threefish256.h>

#define THREEFISH256_BLOCK (32) /* 256-bit block */

/* 64-bit left and right rotation. */
#define ROL(n, r) ((n << r) | (n >> (64 - r)))
#define ROR(n, r) ((n >> r) | (n << (64 - r)))

/* A structure containing a Threefish subkey list. */
typedef struct THREEFISH256_SUBKEYS
{
    UINT256_64 subkey[19];
} THREEFISH256_SUBKEYS;

/* Shorthand macro for context casting. */
#define state(x) ((THREEFISH256_SUBKEYS*)(x->ctx))

BLOCK_CIPHER_CONTEXT* Threefish256_Create(BLOCK_CIPHER* cipher)
{
    /* Allocate space for the Threefish-256 key material. */
    BLOCK_CIPHER_CONTEXT* ctx = salloc(sizeof(BLOCK_CIPHER_CONTEXT));
    if (ctx)
    {
        ctx->cipher = cipher;
        if ((ctx->ctx = salloc(sizeof(THREEFISH256_SUBKEYS)))) return ctx;
        sfree(ctx, sizeof(BLOCK_CIPHER_CONTEXT));
    }

    /* Allocation failed. */
    return 0;
}

int Threefish256_Init(BLOCK_CIPHER_CONTEXT* ctx, UINT256_64* key, size_t keySize, THREEFISH256_PARAMS* params)
{
    size_t t;
    uint64_t keyWords[5];
    uint64_t tweakWords[3];

    /* Only a 256-bit key is permitted. */
    if (keySize != 32) return ORDO_EKEYSIZE;

    /* Read the tweak in the parameters (if none is specified, assume zero). */
    tweakWords[0] = (params == 0) ? 0 : params->tweak[0];
    tweakWords[1] = (params == 0) ? 0 : params->tweak[1];

    /* Read the key. */
    keyWords[0] = key->words[0];
    keyWords[1] = key->words[1];
    keyWords[2] = key->words[2];
    keyWords[3] = key->words[3];

    /* Calculate the extended key and tweak words. */
    keyWords[4] = keyWords[0] ^ keyWords[1] ^ keyWords[2] ^ keyWords[3] ^ (uint64_t)0x1BD11BDAA9FC1A22ULL;
    tweakWords[2] = tweakWords[0] ^ tweakWords[1];

    /* Generate each subkey in a cyclic fashion. */
    for (t = 0; t < 19; t++)
    {
        state(ctx)->subkey[t].words[0] = keyWords[(t + 0) %  5];
        state(ctx)->subkey[t].words[1] = keyWords[(t + 1) %  5] + tweakWords[(t + 0) % 3];
        state(ctx)->subkey[t].words[2] = keyWords[(t + 2) %  5] + tweakWords[(t + 1) % 3];
        state(ctx)->subkey[t].words[3] = keyWords[(t + 3) %  5] + t;
    }

    /* Returns success. */
    return ORDO_ESUCCESS;
}

/* Threefish-256 forward permutation function. */
void Threefish256_Forward(BLOCK_CIPHER_CONTEXT* ctx, UINT256_64* block)
{
    #if ENVIRONMENT_64
    Threefish256_Forward_ASM(block, &state(ctx)->subkey[0]);
    #else
    size_t t;
    uint64_t s;

    /* Initial key whitening. */
    block->words[0] += state(ctx)->subkey[0].words[0];
    block->words[1] += state(ctx)->subkey[0].words[1];
    block->words[2] += state(ctx)->subkey[0].words[2];
    block->words[3] += state(ctx)->subkey[0].words[3];

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
        block->words[0] += state(ctx)->subkey[t * 2 + 1].words[0];
        block->words[1] += state(ctx)->subkey[t * 2 + 1].words[1];
        block->words[2] += state(ctx)->subkey[t * 2 + 1].words[2];
        block->words[3] += state(ctx)->subkey[t * 2 + 1].words[3];

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
        block->words[0] += state(ctx)->subkey[t * 2 + 2].words[0];
        block->words[1] += state(ctx)->subkey[t * 2 + 2].words[1];
        block->words[2] += state(ctx)->subkey[t * 2 + 2].words[2];
        block->words[3] += state(ctx)->subkey[t * 2 + 2].words[3];
    }
    #endif
}

/* Threefish-256 inverse permutation function. */
void Threefish256_Inverse(BLOCK_CIPHER_CONTEXT* ctx, UINT256_64* block)
{
    #if ENVIRONMENT_64
    Threefish256_Inverse_ASM(block, &state(ctx)->subkey[0]);
    #else
    size_t t;
    uint64_t s;

    /* 8 big rounds. */
    for (t = 9; t > 0; t--)
    {
        /* Subkey subtraction. */
        block->words[0] -= state(ctx)->subkey[(t - 1) * 2 + 2].words[0];
        block->words[1] -= state(ctx)->subkey[(t - 1) * 2 + 2].words[1];
        block->words[2] -= state(ctx)->subkey[(t - 1) * 2 + 2].words[2];
        block->words[3] -= state(ctx)->subkey[(t - 1) * 2 + 2].words[3];

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
        block->words[0] -= state(ctx)->subkey[(t - 1) * 2 + 1].words[0];
        block->words[1] -= state(ctx)->subkey[(t - 1) * 2 + 1].words[1];
        block->words[2] -= state(ctx)->subkey[(t - 1) * 2 + 1].words[2];
        block->words[3] -= state(ctx)->subkey[(t - 1) * 2 + 1].words[3];

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
    block->words[0] -= state(ctx)->subkey[0].words[0];
    block->words[1] -= state(ctx)->subkey[0].words[1];
    block->words[2] -= state(ctx)->subkey[0].words[2];
    block->words[3] -= state(ctx)->subkey[0].words[3];
    #endif
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
