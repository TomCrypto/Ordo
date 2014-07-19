/*===-- ofb.c -----------------------------------------*- generic -*- C -*-===*/

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

#include "ordo/primitives/block_modes/ofb.h"

/*===----------------------------------------------------------------------===*/

#if annotation
struct OFB_STATE
{
    unsigned char iv[BLOCK_BLOCK_LEN];
    size_t remaining;
    size_t block_size;
};
#endif /* annotation */

/*===----------------------------------------------------------------------===*/

int ofb_init(struct OFB_STATE *state,
             struct BLOCK_STATE *cipher_state,
             const void *iv, size_t iv_len,
             int dir,
             const void *params)
{
    size_t block_size = block_query(cipher_state->primitive, BLOCK_SIZE_Q, 0);
    state->block_size = block_size;

    if (ofb_query(cipher_state->primitive, IV_LEN_Q, iv_len) != iv_len)
        return ORDO_ARG;

    memset(state->iv, 0x00, block_size);
    memcpy(state->iv, iv, iv_len);

    block_forward(cipher_state, state->iv);
    state->remaining = block_size;

    return ORDO_SUCCESS;
}

void ofb_update(struct OFB_STATE *state,
                struct BLOCK_STATE *cipher_state,
                const unsigned char *in, size_t inlen,
                unsigned char *out, size_t *outlen)
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
        inlen -= process;
        out += process;
        in += process;
    }
}

int ofb_final(struct OFB_STATE *state,
              struct BLOCK_STATE *cipher_state,
              unsigned char *out, size_t *outlen)
{
    if (outlen) *outlen = 0;
    return ORDO_SUCCESS;
}

size_t ofb_query(prim_t cipher,
                 int query, size_t value)
{
    switch(query)
    {
        case IV_LEN_Q: return block_query(cipher, BLOCK_SIZE_Q, 0);
        default      : return 0;
    }
}

size_t ofb_bsize(void)
{
    return sizeof(struct OFB_STATE);
}
