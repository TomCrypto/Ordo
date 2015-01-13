/*===-- ctr.c -----------------------------------------*- generic -*- C -*-===*/

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

#include "ordo/primitives/block_modes/ctr.h"

/*===----------------------------------------------------------------------===*/

#ifdef OPAQUE
struct CTR_STATE
{
    unsigned char keystream[BLOCK_BLOCK_LEN];
    unsigned char block[BLOCK_BLOCK_LEN];
    size_t block_size, ctr_len;
    size_t remaining;
    uint64_t counter;
};
#endif

/*===----------------------------------------------------------------------===*/

/* Assumes zero remaining state bytes, increments the counter and gets a new
 * block's worth of keystream (resetting the remaining field accordingly). */
static void inc_counter(struct BLOCK_STATE *cipher_state,
                        struct CTR_STATE *state)
{
    /* We assert the counter limit will never be reached, since it is always
     * 2^64 maximum (like all other lower limits in the library). */

    uint64_t ctr_le = tole64(state->counter);

    memcpy(state->block, &ctr_le, state->ctr_len);
    memcpy(state->keystream, state->block, state->block_size);
    block_forward(cipher_state, state->keystream);
    state->remaining = state->block_size;

    ++state->counter;
}

int ctr_init(struct CTR_STATE *state,
             struct BLOCK_STATE *cipher_state,
             const void *iv, size_t iv_len,
             int dir,
             const void *params)
{
    int err;

    struct BLOCK_MODE_LIMITS limits;
    struct BLOCK_LIMITS block_lims;

    if ((err = ctr_limits(cipher_state->primitive, &limits)))
        return err;
    if ((err = block_limits(cipher_state->primitive, &block_lims)))
        return err;

    state->block_size = block_lims.block_size;

    if (!limit_check(iv_len, limits.iv_min, limits.iv_max, limits.iv_mul))
        return ORDO_ARG;

    state->ctr_len = state->block_size - iv_len;
    state->remaining = 0;
    state->counter = 0;

    memcpy(offset(state->block, state->ctr_len), iv, iv_len);
    inc_counter(cipher_state, state);

    return ORDO_SUCCESS;
}

void ctr_update(struct CTR_STATE *state,
                struct BLOCK_STATE *cipher_state,
                const void *in, size_t inlen,
                void *out, size_t *outlen)
{
    if (outlen) *outlen = 0;

    while (inlen != 0)
    {
        size_t process;
        void *offset;

        if (state->remaining == 0)
            inc_counter(cipher_state, state);

        process = (inlen < state->remaining) ? inlen : state->remaining;
        offset = offset(state->keystream, state->block_size - state->remaining);

        if (out != in) memcpy(out, in, process);
        xor_buffer(out, offset, process);
        if (outlen) (*outlen) += process;
        state->remaining -= process;
        out = offset(out, process);
        in = offset(in, process);
        inlen -= process;
    }
}

int ctr_final(struct CTR_STATE *state,
              struct BLOCK_STATE *cipher_state,
              void *out, size_t *outlen)
{
    if (outlen) *outlen = 0;
    return ORDO_SUCCESS;
}
