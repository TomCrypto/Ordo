#include <primitives/block_ciphers/threefish256.h>

#include <internal/asm/resolve.h>
#include <common/ordo_errors.h>
#include <common/secure_mem.h>

#include <string.h>

/******************************************************************************/

#define THREEFISH256_BLOCK (32) /* 256-bit block */

/* 64-bit left and right rotation. */
#define ROL(n, r) (((n) << (r)) | ((n) >> (64 - (r))))
#define ROR(n, r) (((n) >> (r)) | ((n) << (64 - (r))))

/* A structure containing a Threefish subkey list. */
struct THREEFISH256_STATE
{
    uint64_t subkey[19][4];
};

struct THREEFISH256_STATE* threefish256_alloc()
{
    return secure_alloc(sizeof(struct THREEFISH256_STATE));
}

/* Macro for subkey generation. */
#define subkey(n, s0, s1, s2, s3, t0, t1) subkeys[n][0] = keyWords[s0]; \
                                          subkeys[n][1] = keyWords[s1] + tweakWords[t0]; \
                                          subkeys[n][2] = keyWords[s2] + tweakWords[t1]; \
                                          subkeys[n][3] = keyWords[s3] + n; \

/* This is the Threefish-256 key schedule. */
void threefish256_key_schedule(const uint64_t key[4], const uint64_t tweak[2], uint64_t subkeys[19][4])
{
    /* Some variables. */
    uint64_t tweakWords[3];
    uint64_t keyWords[5];
    /* Read the key. */
    keyWords[0] = key[0];
    keyWords[1] = key[1];
    keyWords[2] = key[2];
    keyWords[3] = key[3];

    tweakWords[0] = (tweak ? tweak[0] : 0);
    tweakWords[1] = (tweak ? tweak[1] : 0);

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

int threefish256_init(struct THREEFISH256_STATE *state, const uint64_t* key, size_t keySize, const struct THREEFISH256_PARAMS* params)
{
    /* Only a 256-bit key is permitted. */
    if (keySize != 32) return ORDO_KEY_SIZE;

    /* Perform the key schedule (if no tweak is specified, assume zero). */
    threefish256_key_schedule(key, (params == 0) ? 0 : params->tweak, state->subkey);

    /* Returns success. */
    return ORDO_SUCCESS;
}

/* This is the standalone Threefish-256 forward permutation. */
void threefish256_forward_raw(uint64_t block[4], uint64_t subkeys[19][4])
{
    #if defined (THREEFISH256_X86_64_LINUX) || defined (THREEFISH256_X86_64_WINDOWS)
    threefish256_forward_ASM(block, &subkeys[0]);
    #elif defined (THREEFISH256_STANDARD)
    size_t t;
    uint64_t s;

    /* Initial key whitening. */
    block[0] += subkeys[0][0];
    block[1] += subkeys[0][1];
    block[2] += subkeys[0][2];
    block[3] += subkeys[0][3];

    /* 8 big rounds. */
    for (t = 0; t < 9; t++)
    {
        /* MIX */
        block[0] += block[1];
        block[1] = ROL(block[1], 14);
        block[1] ^= block[0];

        block[2] += block[3];
        block[3] = ROL(block[3], 16);
        block[3] ^= block[2];

        /* Permutation */
        s = block[1];
        block[1] = block[3];
        block[3] = s;

        /* MIX */
        block[0] += block[1];
        block[1] = ROL(block[1], 52);
        block[1] ^= block[0];

        block[2] += block[3];
        block[3] = ROL(block[3], 57);
        block[3] ^= block[2];

        /* Permutation */
        s = block[1];
        block[1] = block[3];
        block[3] = s;

        /* MIX */
        block[0] += block[1];
        block[1] = ROL(block[1], 23);
        block[1] ^= block[0];

        block[2] += block[3];
        block[3] = ROL(block[3], 40);
        block[3] ^= block[2];

        /* Permutation */
        s = block[1];
        block[1] = block[3];
        block[3] = s;

        /* MIX */
        block[0] += block[1];
        block[1] = ROL(block[1],  5);
        block[1] ^= block[0];

        block[2] += block[3];
        block[3] = ROL(block[3], 37);
        block[3] ^= block[2];

        /* Permutation */
        s = block[1];
        block[1] = block[3];
        block[3] = s;

        /* Subkey addition. */
        block[0] += subkeys[t * 2 + 1][0];
        block[1] += subkeys[t * 2 + 1][1];
        block[2] += subkeys[t * 2 + 1][2];
        block[3] += subkeys[t * 2 + 1][3];

        /* MIX */
        block[0] += block[1];
        block[1] = ROL(block[1], 25);
        block[1] ^= block[0];

        block[2] += block[3];
        block[3] = ROL(block[3], 33);
        block[3] ^= block[2];

        /* Permutation */
        s = block[1];
        block[1] = block[3];
        block[3] = s;

        /* MIX */
        block[0] += block[1];
        block[1] = ROL(block[1], 46);
        block[1] ^= block[0];

        block[2] += block[3];
        block[3] = ROL(block[3], 12);
        block[3] ^= block[2];

        /* Permutation */
        s = block[1];
        block[1] = block[3];
        block[3] = s;

        /* MIX */
        block[0] += block[1];
        block[1] = ROL(block[1], 58);
        block[1] ^= block[0];

        block[2] += block[3];
        block[3] = ROL(block[3], 22);
        block[3] ^= block[2];

        /* Permutation */
        s = block[1];
        block[1] = block[3];
        block[3] = s;

        /* MIX */
        block[0] += block[1];
        block[1] = ROL(block[1], 32);
        block[1] ^= block[0];

        block[2] += block[3];
        block[3] = ROL(block[3], 32);
        block[3] ^= block[2];

        /* Permutation */
        s = block[1];
        block[1] = block[3];
        block[3] = s;

        /* Subkey addition. */
        block[0] += subkeys[t * 2 + 2][0];
        block[1] += subkeys[t * 2 + 2][1];
        block[2] += subkeys[t * 2 + 2][2];
        block[3] += subkeys[t * 2 + 2][3];
    }
    #endif
}

/* Threefish-256 forward permutation function. */
void threefish256_forward(struct THREEFISH256_STATE *state, uint64_t* block)
{
    threefish256_forward_raw(block, state->subkey);
}

/* This is the standalone Threefish-256 inverse permutation. */
void threefish256_inverse_raw(uint64_t block[4], uint64_t subkeys[19][4])
{
    #if defined (THREEFISH256_X86_64_LINUX) || defined (THREEFISH256_X86_64_WINDOWS)
    threefish256_inverse_ASM(block, &subkeys[0]);
    #elif defined (THREEFISH256_STANDARD)
    size_t t;
    uint64_t s;

    /* 8 big rounds. */
    for (t = 9; t > 0; t--)
    {
        /* Subkey subtraction. */
        block[0] -= subkeys[(t - 1) * 2 + 2][0];
        block[1] -= subkeys[(t - 1) * 2 + 2][1];
        block[2] -= subkeys[(t - 1) * 2 + 2][2];
        block[3] -= subkeys[(t - 1) * 2 + 2][3];

        /* Permutation */
        s = block[1];
        block[1] = block[3];
        block[3] = s;

        /* Inverse MIX */
        block[1] ^= block[0];
        block[1] = ROR(block[1], 32);
        block[0] -= block[1];

        block[3] ^= block[2];
        block[3] = ROR(block[3], 32);
        block[2] -= block[3];

        /* Permutation */
        s = block[1];
        block[1] = block[3];
        block[3] = s;

        /* Inverse MIX */
        block[1] ^= block[0];
        block[1] = ROR(block[1], 58);
        block[0] -= block[1];

        block[3] ^= block[2];
        block[3] = ROR(block[3], 22);
        block[2] -= block[3];

        /* Permutation */
        s = block[1];
        block[1] = block[3];
        block[3] = s;

        /* Inverse MIX */
        block[1] ^= block[0];
        block[1] = ROR(block[1], 46);
        block[0] -= block[1];

        block[3] ^= block[2];
        block[3] = ROR(block[3], 12);
        block[2] -= block[3];

        /* Permutation */
        s = block[1];
        block[1] = block[3];
        block[3] = s;

        /* Inverse MIX */
        block[1] ^= block[0];
        block[1] = ROR(block[1], 25);
        block[0] -= block[1];

        block[3] ^= block[2];
        block[3] = ROR(block[3], 33);
        block[2] -= block[3];

        /* Subkey subtraction. */
        block[0] -= subkeys[(t - 1) * 2 + 1][0];
        block[1] -= subkeys[(t - 1) * 2 + 1][1];
        block[2] -= subkeys[(t - 1) * 2 + 1][2];
        block[3] -= subkeys[(t - 1) * 2 + 1][3];

        /* Permutation */
        s = block[1];
        block[1] = block[3];
        block[3] = s;

        /* Inverse MIX */
        block[1] ^= block[0];
        block[1] = ROR(block[1],  5);
        block[0] -= block[1];

        block[3] ^= block[2];
        block[3] = ROR(block[3], 37);
        block[2] -= block[3];

        /* Permutation */
        s = block[1];
        block[1] = block[3];
        block[3] = s;

        /* Inverse MIX */
        block[1] ^= block[0];
        block[1] = ROR(block[1], 23);
        block[0] -= block[1];

        block[3] ^= block[2];
        block[3] = ROR(block[3], 40);
        block[2] -= block[3];

        /* Permutation */
        s = block[1];
        block[1] = block[3];
        block[3] = s;

        /* Inverse MIX */
        block[1] ^= block[0];
        block[1] = ROR(block[1], 52);
        block[0] -= block[1];

        block[3] ^= block[2];
        block[3] = ROR(block[3], 57);
        block[2] -= block[3];

        /* Permutation */
        s = block[1];
        block[1] = block[3];
        block[3] = s;

        /* Inverse MIX */
        block[1] ^= block[0];
        block[1] = ROR(block[1], 14);
        block[0] -= block[1];

        block[3] ^= block[2];
        block[3] = ROR(block[3], 16);
        block[2] -= block[3];
    }

    /* Final key whitening. */
    block[0] -= subkeys[0][0];
    block[1] -= subkeys[0][1];
    block[2] -= subkeys[0][2];
    block[3] -= subkeys[0][3];
    #endif
}

/* Threefish-256 inverse permutation function. */
void threefish256_inverse(struct THREEFISH256_STATE *state, uint64_t* block)
{
    threefish256_inverse_raw(block, state->subkey);
}

void threefish256_free(struct THREEFISH256_STATE *state)
{
    secure_free(state, sizeof(struct THREEFISH256_STATE));
}

void threefish256_copy(struct THREEFISH256_STATE *dst,
                       const struct THREEFISH256_STATE *src)
{
    memcpy(dst->subkey, src->subkey, sizeof(struct THREEFISH256_STATE));
}

size_t threefish256_key_len(size_t key_len)
{
    return 32; /* 256-bit key only */
}

/* Fills a BLOCK_CIPHER struct with the correct information. */
void threefish256_set_primitive(struct BLOCK_CIPHER* cipher)
{
    make_block_cipher(cipher,
               THREEFISH256_BLOCK,
               (BLOCK_ALLOC)threefish256_alloc,
               (BLOCK_INIT)threefish256_init,
               (BLOCK_UPDATE)threefish256_forward,
               (BLOCK_UPDATE)threefish256_inverse,
               (BLOCK_FREE)threefish256_free,
               (BLOCK_COPY)threefish256_copy,
               (BLOCK_KEYLEN)threefish256_key_len,
               "Threefish-256");
}
