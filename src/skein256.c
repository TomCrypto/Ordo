/*===-- skein256.c ------------------------------------*- generic -*- C -*-===*/

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

#include "ordo/primitives/hash_functions/skein256.h"
#include "ordo/primitives/block_ciphers/threefish256.h"

/*===----------------------------------------------------------------------===*/

#define SKEIN256_INTERNAL (bits(256))
#define SKEIN256_BLOCK    (bits(256))

/* Some UBI block type constants. */
#define SKEIN_UBI_CFG 4
#define SKEIN_UBI_MSG 48
#define SKEIN_UBI_OUT 63

/* This also represents the default configuration block, to avoid recreating
 * it in case the parameters do not specify a different configuration block. */
static const uint64_t skein256_iv[4] =
{
    UINT64_C(0xFC9DA860D048B449), UINT64_C(0x2FCA66479FA7D833),
    UINT64_C(0xB33BC3896656840F), UINT64_C(0x6A54E920FDE8DA69)
};

/* Note this assumes "first" and "final" are boolean (0 or 1). The result is a
 * UBI-compliant tweak, however with a message length only up to 2^64 bits. */
static void make_tweak(uint64_t tweak[2],
                       uint64_t type,
                       uint64_t position,
                       uint64_t first,
                       uint64_t final) HOT_CODE;

static void skein256_compress(const uint64_t * RESTRICT block,
                              uint64_t * RESTRICT state,
                              uint64_t * RESTRICT tweak)
HOT_CODE;

#ifdef OPAQUE
struct SKEIN256_STATE
{
    uint64_t state[4];
    uint64_t block[4];
    uint64_t block_len;
    uint64_t msg_len;
};
#endif

/*===----------------------------------------------------------------------===*/

int skein256_init(struct SKEIN256_STATE *state,
                  const struct SKEIN256_PARAMS *params)
{
    state->block_len = 0;
    state->msg_len = 0;

    if (params)
    {
        uint64_t tweak[2];

        if (bits(params->out_len) != SKEIN256_INTERNAL)
            return ORDO_ARG;

        /* Generate the initial state from the configuration block. */
        memset(state->state, 0, SKEIN256_BLOCK);
        memcpy(state->block, params, SKEIN256_BLOCK);
        make_tweak(tweak, SKEIN_UBI_CFG, SKEIN256_BLOCK, 1, 1);
        skein256_compress(state->block, state->state, tweak);
    }
    else
    {
        /* No parameters, use default configuration block. */
        memcpy(state->state, skein256_iv, SKEIN256_INTERNAL);

        /* Configuration block is actually little-endian. */
        state->state[0] = fmle64(state->state[0]);
        state->state[1] = fmle64(state->state[1]);
        state->state[2] = fmle64(state->state[2]);
        state->state[3] = fmle64(state->state[3]);
    }

    return ORDO_SUCCESS;
}

void skein256_update(struct SKEIN256_STATE *state,
                     const void *buffer, size_t len)
{
    if (!len) return;

    if (state->block_len + len > SKEIN256_BLOCK)
    {
        size_t pad = (size_t)(SKEIN256_BLOCK - state->block_len);
        uint64_t tweak[2];

        memcpy(offset(state->block, state->block_len), buffer, pad);
        state->msg_len += pad;

        make_tweak(tweak,
                   SKEIN_UBI_MSG,
                   state->msg_len,
                   state->msg_len <= SKEIN256_BLOCK,
                   0); /* can't be the last block */

        skein256_compress(state->block, state->state, tweak);
        state->block_len = 0;

        buffer = offset(buffer, pad);
        len -= pad;

        /* Do NOT process the final block. */
        while (len > SKEIN256_BLOCK)
        {
            memcpy(state->block, buffer, SKEIN256_BLOCK);
            state->msg_len += SKEIN256_BLOCK;

            make_tweak(tweak,
                       SKEIN_UBI_MSG,
                       state->msg_len,
                       state->msg_len <= SKEIN256_BLOCK,
                       0);

            skein256_compress(state->block, state->state, tweak);

            buffer = offset(buffer, SKEIN256_BLOCK);
            len -= SKEIN256_BLOCK;
        }
    }

    memcpy(offset(state->block, state->block_len), buffer, len);
    state->block_len += len;
}

void skein256_final(struct SKEIN256_STATE *state,
                    void *digest)
{
    uint64_t tweak[2];

    /* Here, we need to process one complete block - the Skein specification
     * mandates zero-fill, so erase any residual input data in the state. */
    memset(offset(state->block, state->block_len),
           0x00,
           (size_t)(SKEIN256_BLOCK - state->block_len));

    /* However, only the actual input data counts towards the length. */
    state->msg_len += state->block_len;

    make_tweak(tweak,
               SKEIN_UBI_MSG,
               state->msg_len,
               state->msg_len <= SKEIN256_BLOCK,
               1); /* this'll be the last block */

    skein256_compress(state->block, state->state, tweak);

    {
        uint64_t out[4];

        state->block[0] = 0;
        state->block[1] = 0;
        state->block[2] = 0;
        state->block[3] = 0;

        out[0] = state->state[0];
        out[1] = state->state[1];
        out[2] = state->state[2];
        out[3] = state->state[3];

        make_tweak(tweak, SKEIN_UBI_OUT, sizeof(uint64_t), 1, 1);
        skein256_compress(state->block, out, tweak);
        memcpy(digest, out, SKEIN256_BLOCK);
    }
}

/*===----------------------------------------------------------------------===*/

void make_tweak(uint64_t tweak[2],
                uint64_t type,
                uint64_t position,
                uint64_t first,
                uint64_t final)
{
    tweak[0] = tole64(position);
    tweak[1] = tole64((final << 63) | (first << 62) | (type  << 56));
}

void skein256_compress(const uint64_t * RESTRICT block,
                       uint64_t * RESTRICT state,
                       uint64_t * RESTRICT tweak)
{
    struct THREEFISH256_PARAMS params;
    struct THREEFISH256_STATE cipher;
    params.tweak[0] = tweak[0];
    params.tweak[1] = tweak[1];

    threefish256_init(&cipher, state, SKEIN256_INTERNAL, &params);

    memcpy(state, block, SKEIN256_INTERNAL);
    threefish256_forward(&cipher, state);
    threefish256_final(&cipher);

    xor_buffer(state, block, SKEIN256_INTERNAL);
}
