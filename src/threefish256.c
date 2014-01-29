//===-- threefish256.c --------------------------------*- generic -*- C -*-===//

#include "ordo/primitives/block_ciphers/threefish256.h"

/// @cond
#include "ordo/internal/implementation.h"
/// @endcond

//===----------------------------------------------------------------------===//

#define THREEFISH256_BLOCK (bits(256))

struct THREEFISH256_STATE
{
    uint64_t subkey[19 * 4];
};

static void threefish256_key_schedule(const uint64_t key[4],
                                      const uint64_t tweak[2],
                                      uint64_t *subkeys) HOT_CODE;

static void threefish256_forward_C(uint64_t block[4],
                                   const uint64_t *subkeys) HOT_CODE;

static void threefish256_inverse_C(uint64_t block[4],
                                   const uint64_t *subkeys) HOT_CODE;

//===----------------------------------------------------------------------===//

struct THREEFISH256_STATE *threefish256_alloc(void)
{
    return mem_alloc(sizeof(struct THREEFISH256_STATE));
}

int threefish256_init(struct THREEFISH256_STATE *state,
                      const uint64_t *key, size_t key_len,
                      const struct THREEFISH256_PARAMS *params)
{
    if (threefish256_query(KEY_LEN_Q, key_len) == key_len)
    {
        const uint64_t *tweak = params == 0 ? 0 : params->tweak;
        threefish256_key_schedule(key, tweak, state->subkey);

        return ORDO_SUCCESS;
    }

    return ORDO_KEY_LEN;
}

void threefish256_forward(const struct THREEFISH256_STATE *state,
                          uint64_t *block)
{
    threefish256_forward_C(block, state->subkey);
}

void threefish256_inverse(const struct THREEFISH256_STATE *state,
                          uint64_t *block)
{
    threefish256_inverse_C(block, state->subkey);
}

void threefish256_final(struct THREEFISH256_STATE *state)
{
    return;
}

void threefish256_free(struct THREEFISH256_STATE *state)
{
    mem_free(state);
}

void threefish256_copy(struct THREEFISH256_STATE *dst,
                       const struct THREEFISH256_STATE *src)
{
    memcpy(dst, src, sizeof(struct THREEFISH256_STATE));
}

size_t threefish256_query(int query, size_t value)
{
    switch(query)
    {
        case BLOCK_SIZE_Q: return THREEFISH256_BLOCK;
        case KEY_LEN_Q   : return 32;
        default          : return 0;
    }
}

//===----------------------------------------------------------------------===//

void threefish256_forward_C(uint64_t block[4], const uint64_t *subkeys)
{
    size_t t;

    block[0] = tole64(block[0]);
    block[1] = tole64(block[1]);
    block[2] = tole64(block[2]);
    block[3] = tole64(block[3]);

    block[0] += subkeys[0 * 4 + 0];
    block[1] += subkeys[0 * 4 + 1];
    block[2] += subkeys[0 * 4 + 2];
    block[3] += subkeys[0 * 4 + 3];

    for (t = 0; t < 9; t++)
    {
        uint64_t s;

        block[0] += block[1];
        block[1] = rol64(block[1], 14);
        block[1] ^= block[0];

        block[2] += block[3];
        block[3] = rol64(block[3], 16);
        block[3] ^= block[2];

        s = block[1];
        block[1] = block[3];
        block[3] = s;

        block[0] += block[1];
        block[1] = rol64(block[1], 52);
        block[1] ^= block[0];

        block[2] += block[3];
        block[3] = rol64(block[3], 57);
        block[3] ^= block[2];

        s = block[1];
        block[1] = block[3];
        block[3] = s;

        block[0] += block[1];
        block[1] = rol64(block[1], 23);
        block[1] ^= block[0];

        block[2] += block[3];
        block[3] = rol64(block[3], 40);
        block[3] ^= block[2];

        s = block[1];
        block[1] = block[3];
        block[3] = s;

        block[0] += block[1];
        block[1] = rol64(block[1],  5);
        block[1] ^= block[0];

        block[2] += block[3];
        block[3] = rol64(block[3], 37);
        block[3] ^= block[2];

        s = block[1];
        block[1] = block[3];
        block[3] = s;

        block[0] += subkeys[(t * 2 + 1) * 4 + 0];
        block[1] += subkeys[(t * 2 + 1) * 4 + 1];
        block[2] += subkeys[(t * 2 + 1) * 4 + 2];
        block[3] += subkeys[(t * 2 + 1) * 4 + 3];

        block[0] += block[1];
        block[1] = rol64(block[1], 25);
        block[1] ^= block[0];

        block[2] += block[3];
        block[3] = rol64(block[3], 33);
        block[3] ^= block[2];

        s = block[1];
        block[1] = block[3];
        block[3] = s;

        block[0] += block[1];
        block[1] = rol64(block[1], 46);
        block[1] ^= block[0];

        block[2] += block[3];
        block[3] = rol64(block[3], 12);
        block[3] ^= block[2];

        s = block[1];
        block[1] = block[3];
        block[3] = s;

        block[0] += block[1];
        block[1] = rol64(block[1], 58);
        block[1] ^= block[0];

        block[2] += block[3];
        block[3] = rol64(block[3], 22);
        block[3] ^= block[2];

        s = block[1];
        block[1] = block[3];
        block[3] = s;

        block[0] += block[1];
        block[1] = rol64(block[1], 32);
        block[1] ^= block[0];

        block[2] += block[3];
        block[3] = rol64(block[3], 32);
        block[3] ^= block[2];

        s = block[1];
        block[1] = block[3];
        block[3] = s;

        block[0] += subkeys[(t * 2 + 2) * 4 + 0];
        block[1] += subkeys[(t * 2 + 2) * 4 + 1];
        block[2] += subkeys[(t * 2 + 2) * 4 + 2];
        block[3] += subkeys[(t * 2 + 2) * 4 + 3];
    }

    block[0] = fmle64(block[0]);
    block[1] = fmle64(block[1]);
    block[2] = fmle64(block[2]);
    block[3] = fmle64(block[3]);
}

void threefish256_inverse_C(uint64_t block[4], const uint64_t *subkeys)
{
    size_t t;

    block[0] = tole64(block[0]);
    block[1] = tole64(block[1]);
    block[2] = tole64(block[2]);
    block[3] = tole64(block[3]);

    for (t = 9; t > 0; t--)
    {
        uint64_t s;

        block[0] -= subkeys[((t - 1) * 2 + 2) * 4 + 0];
        block[1] -= subkeys[((t - 1) * 2 + 2) * 4 + 1];
        block[2] -= subkeys[((t - 1) * 2 + 2) * 4 + 2];
        block[3] -= subkeys[((t - 1) * 2 + 2) * 4 + 3];

        s = block[1];
        block[1] = block[3];
        block[3] = s;

        block[1] ^= block[0];
        block[1] = ror64(block[1], 32);
        block[0] -= block[1];

        block[3] ^= block[2];
        block[3] = ror64(block[3], 32);
        block[2] -= block[3];

        s = block[1];
        block[1] = block[3];
        block[3] = s;

        block[1] ^= block[0];
        block[1] = ror64(block[1], 58);
        block[0] -= block[1];

        block[3] ^= block[2];
        block[3] = ror64(block[3], 22);
        block[2] -= block[3];

        s = block[1];
        block[1] = block[3];
        block[3] = s;

        block[1] ^= block[0];
        block[1] = ror64(block[1], 46);
        block[0] -= block[1];

        block[3] ^= block[2];
        block[3] = ror64(block[3], 12);
        block[2] -= block[3];

        s = block[1];
        block[1] = block[3];
        block[3] = s;

        block[1] ^= block[0];
        block[1] = ror64(block[1], 25);
        block[0] -= block[1];

        block[3] ^= block[2];
        block[3] = ror64(block[3], 33);
        block[2] -= block[3];

        block[0] -= subkeys[((t - 1) * 2 + 1) * 4 + 0];
        block[1] -= subkeys[((t - 1) * 2 + 1) * 4 + 1];
        block[2] -= subkeys[((t - 1) * 2 + 1) * 4 + 2];
        block[3] -= subkeys[((t - 1) * 2 + 1) * 4 + 3];

        s = block[1];
        block[1] = block[3];
        block[3] = s;

        block[1] ^= block[0];
        block[1] = ror64(block[1],  5);
        block[0] -= block[1];

        block[3] ^= block[2];
        block[3] = ror64(block[3], 37);
        block[2] -= block[3];

        s = block[1];
        block[1] = block[3];
        block[3] = s;

        block[1] ^= block[0];
        block[1] = ror64(block[1], 23);
        block[0] -= block[1];

        block[3] ^= block[2];
        block[3] = ror64(block[3], 40);
        block[2] -= block[3];

        s = block[1];
        block[1] = block[3];
        block[3] = s;

        block[1] ^= block[0];
        block[1] = ror64(block[1], 52);
        block[0] -= block[1];

        block[3] ^= block[2];
        block[3] = ror64(block[3], 57);
        block[2] -= block[3];

        s = block[1];
        block[1] = block[3];
        block[3] = s;

        block[1] ^= block[0];
        block[1] = ror64(block[1], 14);
        block[0] -= block[1];

        block[3] ^= block[2];
        block[3] = ror64(block[3], 16);
        block[2] -= block[3];
    }

    block[0] -= subkeys[0 * 4 + 0];
    block[1] -= subkeys[0 * 4 + 1];
    block[2] -= subkeys[0 * 4 + 2];
    block[3] -= subkeys[0 * 4 + 3];

    block[0] = fmle64(block[0]);
    block[1] = fmle64(block[1]);
    block[2] = fmle64(block[2]);
    block[3] = fmle64(block[3]);
}

#define subkey(n, s0, s1, s2, s3, t0, t1)\
    subkeys[n * 4 + 0] = key_w[s0]; \
    subkeys[n * 4 + 1] = key_w[s1] + tweak_w[t0]; \
    subkeys[n * 4 + 2] = key_w[s2] + tweak_w[t1]; \
    subkeys[n * 4 + 3] = key_w[s3] + n; \

#define K_S (0x1BD11BDAA9FC1A22ULL)

void threefish256_key_schedule(const uint64_t key[4],
                               const uint64_t tweak[2],
                               uint64_t *subkeys)
{
    uint64_t tweak_w[3];
    uint64_t key_w[5];

    key_w[0] = tole64(key[0]);
    key_w[1] = tole64(key[1]);
    key_w[2] = tole64(key[2]);
    key_w[3] = tole64(key[3]);

    tweak_w[0] = (tweak ? tole64(tweak[0]) : 0);
    tweak_w[1] = (tweak ? tole64(tweak[1]) : 0);

    key_w[4] = key_w[0] ^ key_w[1] ^ key_w[2] ^ key_w[3] ^ K_S;
    tweak_w[2] = tweak_w[0] ^ tweak_w[1];

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
