/*===-- ctr.c -----------------------------------------*- generic -*- C -*-===*/

#include "ordo/primitives/block_modes/ctr.h"

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

/*===----------------------------------------------------------------------===*/

#if annotation
struct CTR_STATE
{
    unsigned char buf[BLOCK_BLOCK_LEN];
    unsigned char counter[BLOCK_BLOCK_LEN];
    size_t remaining;
    size_t block_size;
};
#endif /* annotation */

/*===----------------------------------------------------------------------===*/

int ctr_init(struct CTR_STATE *state,
             struct BLOCK_STATE *cipher_state,
             const void *iv, size_t iv_len,
             int dir,
             const void *params)
{
    size_t block_size = block_query(cipher_state->primitive, BLOCK_SIZE_Q, 0);
    state->block_size = block_size;
    state->remaining = 0;

    if (ctr_query(cipher_state->primitive, IV_LEN_Q, iv_len) != iv_len)
        return ORDO_ARG;

    memset(state->buf, 0x00, block_size);
    memcpy(state->buf, iv, iv_len);
    memcpy(state->counter, state->buf, block_size);

    block_forward(cipher_state, state->buf);
    state->remaining = block_size;

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
        size_t block_size = state->block_size;
        size_t process = 0;

        if (state->remaining == 0)
        {
            inc_buffer(state->counter, block_size);
            memcpy(state->buf, state->counter, block_size);
            block_forward(cipher_state, state->buf);
            state->remaining = block_size;
        }

        process = (inlen < state->remaining) ? inlen : state->remaining;

        if (out != in) memcpy(out, in, process);
        xor_buffer(out, offset(state->buf, block_size - state->remaining), process);
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
    switch(query)
    {
        case IV_LEN_Q: return block_query(cipher, BLOCK_SIZE_Q, 0);
        default      : return 0;
    }
}

size_t ctr_bsize(void)
{
    return sizeof(struct CTR_STATE);
}
