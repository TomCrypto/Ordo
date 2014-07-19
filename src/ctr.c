/*===-- ctr.c -----------------------------------------*- generic -*- C -*-===*/

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

#include "ordo/primitives/block_modes/ctr.h"

/*===----------------------------------------------------------------------===*/

#if annotation
struct CTR_STATE
{
    unsigned char keystream[BLOCK_BLOCK_LEN];
    unsigned char block[BLOCK_BLOCK_LEN];
    size_t block_size, ctr_len;
    size_t remaining;
    uint64_t counter;
};
#endif /* annotation */

/*===----------------------------------------------------------------------===*/

/* Assumes zero remaining state bytes, increments the counter and gets a new
 * block's worth of keystream (resetting the remaining field accordingly). */
static void inc_counter(struct BLOCK_STATE *cipher_state,
                        struct CTR_STATE *state)
{
    /* We assert the counter limit will never be reached, since it is always
     * 2^64 maximum (like all other lower limits in the library). */

    uint64_t ctr = tole64(state->counter);

    memcpy(state->block, &ctr, state->ctr_len);
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
    size_t block_size = block_query(cipher_state->primitive, BLOCK_SIZE_Q, 0);
    if (ctr_query(cipher_state->primitive, IV_LEN_Q, iv_len) != iv_len)
        return ORDO_ARG;

    state->ctr_len = block_size - iv_len;
    state->block_size = block_size;
    state->remaining = 0;
    state->counter = 0;

    memcpy(offset(state->block, state->ctr_len), iv, iv_len);
    inc_counter(cipher_state, state);

    return ORDO_SUCCESS;
}

void ctr_update(struct CTR_STATE *state,
                struct BLOCK_STATE *cipher_state,
                const unsigned char *in, size_t inlen,
                unsigned char *out, size_t *outlen)
{
    if (outlen) *outlen = 0;

    while (inlen != 0)
    {
        size_t process;
        void *offset;

        if (state->remaining == 0)
            inc_counter(cipher_state, state);

        process = (inlen < state->remaining) ? inlen : state->remaining;
        offset = offset(state->block, state->block_size - state->remaining);

        if (out != in) memcpy(out, in, process);
        xor_buffer(out, offset, process);
        if (outlen) (*outlen) += process;
        state->remaining -= process;
        inlen -= process;
        out += process;
        in += process;
    }
}

int ctr_final(struct CTR_STATE *state,
              struct BLOCK_STATE *cipher_state,
              unsigned char *out, size_t *outlen)
{
    if (outlen) *outlen = 0;
    return ORDO_SUCCESS;
}

size_t ctr_query(prim_t cipher,
                 int query, size_t value)
{
    size_t block_size = block_query(cipher, BLOCK_SIZE_Q, 0);

    switch(query)
    {
        case IV_LEN_Q: return block_size - bits(64);
        default      : return 0;
    }
}

size_t ctr_bsize(void)
{
    return sizeof(struct CTR_STATE);
}
