#include "ordo/primitives/hash_functions/skein256.h"

#include "ordo/primitives/block_ciphers/threefish256.h"

#include "ordo/internal/mem.h"

#include "ordo/common/errors.h"
#include "ordo/common/utils.h"
#include "ordo/common/query.h"

#include <string.h>

/******************************************************************************/

#define SKEIN256_INTERNAL (bits(256))
#define SKEIN256_BLOCK    (bits(256))

/* Some UBI block type constants. */
#define SKEIN_UBI_CFG 4
#define SKEIN_UBI_MSG 48
#define SKEIN_UBI_OUT 63

/* This also represents the default configuration block, to avoid recreating it
 * in case the parameters do not specify a different configuration block. */
static const uint64_t skein256_iv[4] = {
    0xFC9DA860D048B449, 0x2FCA66479FA7D833,
    0xB33BC3896656840F, 0x6A54E920FDE8DA69
};

/* Note this assumes "first" and "final" are boolean (0 or 1). The result is a
 * UBI-compliant tweak, however with a message length only up to 2^64 bits. */
static void make_tweak(uint64_t tweak[2],
                       uint64_t type,
                       uint64_t position,
                       uint64_t first,
                       uint64_t final)
{
    tweak[0] = position;
    tweak[1] = (final << 63) | (first << 62) | (type  << 56);
}

static void skein256_compress(const uint64_t *block,
                              uint64_t *state,
                              uint64_t *tweak)
__attribute__((hot));

void skein256_compress(const uint64_t *block, uint64_t *state, uint64_t *tweak)
{
    uint64_t subkeys[19][4];

    threefish256_key_schedule(state, tweak, subkeys);

    memcpy(state, block, SKEIN256_INTERNAL);

    threefish256_forward_raw(state, subkeys);

    xor_buffer(state, block, SKEIN256_INTERNAL);
}

/******************************************************************************/

struct SKEIN256_STATE
{
    uint64_t state[4];
    uint64_t block[4];
    uint64_t block_len;
    uint64_t msg_len;
    uint64_t out_len;
};

struct SKEIN256_STATE *skein256_alloc(void)
{
    return mem_alloc(sizeof(struct SKEIN256_STATE));
}

int skein256_init(struct SKEIN256_STATE *state,
                  const struct SKEIN256_PARAMS *params)
{
    state->block_len = 0;
    state->msg_len = 0;

    if (params)
    {
        uint64_t tweak[2];

        if (bits(params->out_len) == 0) return ORDO_ARG;

        /* Save the output length, in bytes. */
        state->out_len = bits(params->out_len);

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
        state->out_len = SKEIN256_INTERNAL;
    }

    return ORDO_SUCCESS;
}

void skein256_update(struct SKEIN256_STATE *state,
                     const void *buffer,
                     size_t size)
{
    if (state->block_len + size > SKEIN256_BLOCK)
    {
        size_t pad = SKEIN256_BLOCK - state->block_len;
        uint64_t tweak[2];

        memcpy(offset(state->block, state->block_len), buffer, pad);
        state->msg_len += pad;

        make_tweak(tweak,
                   SKEIN_UBI_MSG,
                   state->msg_len,
                   state->msg_len <= SKEIN256_BLOCK,
                   0 /* can't be the last block */);

        skein256_compress(state->block, state->state, tweak);
        state->block_len = 0;

        /* Offset the message accordingly. */
        buffer = offset(buffer, pad);
        size -= pad;

        /* Do NOT process the final block. */
        while (size > SKEIN256_BLOCK)
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
            size -= SKEIN256_BLOCK;
        }
    }

    memcpy(offset(state->block, state->block_len), buffer, size);
    state->block_len += size;
}

void skein256_final(struct SKEIN256_STATE *state,
                    void *digest)
{
    uint64_t tweak[2];
    uint64_t ctr = 0;
    uint64_t out[4];

    /* Here, we need to process one complete block - the Skein specification
     * mandates zero-fill, so erase any residual input data in the state. */
    memset(offset(state->block, state->block_len),
           0x00,
           SKEIN256_BLOCK - state->block_len);

    /* However, only the actual input data counts towards the length. */
    state->msg_len += state->block_len;

    make_tweak(tweak,
               SKEIN_UBI_MSG,
               state->msg_len,
               state->msg_len <= SKEIN256_BLOCK,
               1 /* this'll be the last block */);

    skein256_compress(state->block, state->state, tweak);

    /* We'll use the state block as scratch storage now. All words should be
     * zero, but the first one will be modified while creating the output. */
    memset(state->block, 0x00, SKEIN256_BLOCK);

    /* This is to implement the arbitrary output length feature. This is done
     * by (loosely stated) running the Threefish-256 cipher in counter mode. */
    while (state->out_len != 0)
    {
        size_t cpy = min(state->out_len, SKEIN256_BLOCK);

        state->block[0] = ctr++;
        memcpy(out, state->state, SKEIN256_INTERNAL);

        make_tweak(tweak, SKEIN_UBI_OUT, sizeof(uint64_t), 1, 1);
        skein256_compress(state->block, out, tweak);

        memcpy(offset(digest, (ctr - 1) * SKEIN256_BLOCK), out, cpy);
        state->out_len -= cpy; /* Will always reach zero, see cpy. */
    }
}

void skein256_free(struct SKEIN256_STATE *state)
{
    mem_free(state);
}

void skein256_copy(struct SKEIN256_STATE *dst,
                   const struct SKEIN256_STATE *src)
{
    memcpy(dst, src, sizeof(struct SKEIN256_STATE));
}

size_t skein256_query(int query, size_t value)
{
    switch(query)
    {
        case BLOCK_SIZE: return SKEIN256_BLOCK;
        case DIGEST_LEN: return SKEIN256_INTERNAL;
        
        default: return 0;
    }
}
