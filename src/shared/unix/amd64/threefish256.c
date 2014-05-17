/*===-- threefish256.c ----------------------*- shared/unix/amd64 -*- C -*-===*/

#include "ordo/primitives/block_ciphers/threefish256.h"

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

/*===----------------------------------------------------------------------===*/

#define THREEFISH256_BLOCK (bits(256))

struct THREEFISH256_STATE
{
    uint64_t subkey[19 * 4];
};

static void threefish256_key_schedule(const uint64_t key[4],
                                      const uint64_t tweak[2],
                                      uint64_t *subkeys) HOT_CODE;

extern void threefish256_forward_ASM(void *block, const void *subkeys);
extern void threefish256_inverse_ASM(void *block, const void *subkeys);

/*===----------------------------------------------------------------------===*/

int threefish256_init(struct THREEFISH256_STATE *state,
                      const uint64_t *key, size_t key_len,
                      const struct THREEFISH256_PARAMS *params)
{
    if (threefish256_query(KEY_LEN_Q, key_len) != key_len)
    {
        return ORDO_KEY_LEN;
    }

    threefish256_key_schedule(key, (params == 0) ? 0 : params->tweak,
                              state->subkey);

    return ORDO_SUCCESS;
}

void threefish256_forward(const struct THREEFISH256_STATE *state, uint64_t *block)
{
    threefish256_forward_ASM(block, state->subkey);
}

void threefish256_inverse(const struct THREEFISH256_STATE *state, uint64_t *block)
{
    threefish256_inverse_ASM(block, state->subkey);
}

void threefish256_final(struct THREEFISH256_STATE *state)
{
    return;
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

/*===----------------------------------------------------------------------===*/

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
