/*===-- ofb.c -----------------------------------------*- generic -*- C -*-===*/

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

#include "ordo/primitives/block_modes/ofb.h"

/*===----------------------------------------------------------------------===*/

#ifdef OPAQUE
struct OFB_STATE
{
    unsigned char iv[BLOCK_BLOCK_LEN];
    size_t remaining;
    size_t block_size;
};
#endif

/*===----------------------------------------------------------------------===*/

int ofb_init(struct OFB_STATE *state,
             struct BLOCK_STATE *cipher_state,
             const void *iv, size_t iv_len,
             int dir,
             const void *params)
{
    int err;

    struct BLOCK_MODE_LIMITS limits;
    struct BLOCK_LIMITS block_lims;

    if ((err = ofb_limits(cipher_state->primitive, &limits)))
        return err;
    if ((err = block_limits(cipher_state->primitive, &block_lims)))
        return err;

    state->block_size = block_lims.block_size;

    if (!limit_check(iv_len, limits.iv_min, limits.iv_max, limits.iv_mul))
        return ORDO_ARG;

    memset(state->iv, 0x00, state->block_size);
    memcpy(state->iv, iv, iv_len);

    block_forward(cipher_state, state->iv);
    state->remaining = state->block_size;

    return ORDO_SUCCESS;
}

void ofb_update(struct OFB_STATE *state,
                struct BLOCK_STATE *cipher_state,
                const void *in, size_t inlen,
                void *out, size_t *outlen)
{
    if (outlen) *outlen = 0;

    while (inlen != 0)
    {
        size_t block_size = state->block_size;
        size_t process = 0;

        /* Is there data left? */
        if (state->remaining == 0)
        {
            block_forward(cipher_state, state->iv);
            state->remaining = block_size;
        }

        process = (inlen < state->remaining) ? inlen : state->remaining;

        if (out != in) memcpy(out, in, process);
        xor_buffer(out, offset(state->iv, block_size - state->remaining), process);
        if (outlen) (*outlen) += process;
        state->remaining -= process;
        out = offset(out, process);
        in = offset(in, process);
        inlen -= process;
    }
}

int ofb_final(struct OFB_STATE *state,
              struct BLOCK_STATE *cipher_state,
              void *out, size_t *outlen)
{
    if (outlen) *outlen = 0;
    return ORDO_SUCCESS;
}
