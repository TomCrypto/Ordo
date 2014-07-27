/*===-- threefish256.c ----------------------------*- win32/amd64 -*- C -*-===*/

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

#include "ordo/primitives/block_ciphers/threefish256.h"

/*===----------------------------------------------------------------------===*/

static void threefish256_key_schedule(const uint64_t *key,
                                      const uint64_t *tweak,
                                      uint64_t * RESTRICT subkeys)
HOT_CODE;

extern void threefish256_forward_ASM(uint64_t * RESTRICT block,
                                     const uint64_t * RESTRICT subkeys);
extern void threefish256_inverse_ASM(uint64_t * RESTRICT block,
                                     const uint64_t * RESTRICT subkeys);

#ifdef OPAQUE
struct THREEFISH256_STATE
{
    uint64_t subkey[19 * 4];
};
#endif

/*===----------------------------------------------------------------------===*/

int threefish256_init(struct THREEFISH256_STATE *state,
                      const void *key, size_t key_len,
                      const struct THREEFISH256_PARAMS *params)
{
    uint64_t data[4];

    if (threefish256_query(KEY_LEN_Q, key_len) != key_len)
        return ORDO_KEY_LEN;

    memcpy(data, key, sizeof(data));
    threefish256_key_schedule(data, (params == 0) ? 0 : params->tweak,
                              state->subkey);

    return ORDO_SUCCESS;
}

void threefish256_forward(const struct THREEFISH256_STATE *state,
                          void *block)
{
    uint64_t data[4];

    memcpy(data, block, sizeof(data));
    threefish256_forward_ASM(data, state->subkey);
    memcpy(block, data, sizeof(data));
}

void threefish256_inverse(const struct THREEFISH256_STATE *state,
                          void *block)
{
    uint64_t data[4];

    memcpy(data, block, sizeof(data));
    threefish256_inverse_ASM(data, state->subkey);
    memcpy(block, data, sizeof(data));
}

void threefish256_final(struct THREEFISH256_STATE *state)
{
    return;
}

/*===----------------------------------------------------------------------===*/

#define subkey(n, s0, s1, s2, s3, t0, t1)\
    subkeys[n * 4 + 0] = key_w[s0]; \
    subkeys[n * 4 + 1] = key_w[s1] + tweak_w[t0]; \
    subkeys[n * 4 + 2] = key_w[s2] + tweak_w[t1]; \
    subkeys[n * 4 + 3] = key_w[s3] + n; \

#define K_S (UINT64_C(0x1BD11BDAA9FC1A22))

void threefish256_key_schedule(const uint64_t *key,
                               const uint64_t *tweak,
                               uint64_t * RESTRICT subkeys)
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
