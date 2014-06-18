/*===-- cfb.c -----------------------------------------*- generic -*- C -*-===*/

#include "ordo/primitives/block_modes/cfb.h"

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

/*===----------------------------------------------------------------------===*/

#if annotation
struct CFB_STATE
{
    unsigned char iv[BLOCK_BLOCK_LEN];
    unsigned char tmp[BLOCK_BLOCK_LEN];
    size_t remaining;
    size_t block_size;
    int direction;
};
#endif /* annotation */

/*===----------------------------------------------------------------------===*/

int cfb_init(struct CFB_STATE *state,
             struct BLOCK_STATE *cipher_state,
             const void *iv, size_t iv_len,
             int dir,
             const void *params)
{
    size_t block_size = block_query(cipher_state->primitive, BLOCK_SIZE_Q, 0);
    state->block_size = block_size;
    state->remaining = 0;

    if (cfb_query(cipher_state->primitive, IV_LEN_Q, iv_len) != iv_len)
        return ORDO_ARG;

    state->direction = dir;

    memset(state->iv, 0x00, block_size);
    memcpy(state->iv, iv, iv_len);

    block_forward(cipher_state, state->iv);
    state->remaining = block_size;

    return ORDO_SUCCESS;
}

static void cfb_encrypt_update(struct CFB_STATE *state,
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
            block_forward(cipher_state, state->iv);
            state->remaining = block_size;
        }

        process = (inlen < state->remaining) ? inlen : state->remaining;

        if (out != in) memcpy(out, in, process);
        xor_buffer(out, offset(state->iv, block_size - state->remaining), process);
        memcpy(offset(state->iv, block_size - state->remaining), out, process);
        if (outlen) (*outlen) += process;
        state->remaining -= process;
        inlen -= process;
        out += process;
        in += process;
    }
}

static void cfb_decrypt_update(struct CFB_STATE *state,
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
            block_forward(cipher_state, state->iv);
            state->remaining = block_size;
        }

        process = (inlen < state->remaining) ? inlen : state->remaining;

        if (out != in) memcpy(out, in, process);
        memcpy(state->tmp, in, process);
        xor_buffer(out, offset(state->iv, block_size - state->remaining), process);
        memcpy(offset(state->iv, block_size - state->remaining), state->tmp, process);
        if (outlen) (*outlen) += process;
        state->remaining -= process;
        inlen -= process;
        out += process;
        in += process;
    }
}

void cfb_update(struct CFB_STATE *state,
                struct BLOCK_STATE *cipher_state,
                const unsigned char *in, size_t inlen,
                unsigned char *out, size_t *outlen)
{
    (state->direction
     ? cfb_encrypt_update(state, cipher_state, in, inlen, out, outlen)
     : cfb_decrypt_update(state, cipher_state, in, inlen, out, outlen));
}

int cfb_final(struct CFB_STATE *state,
              struct BLOCK_STATE *cipher_state,
              unsigned char *out, size_t *outlen)
{
    if (outlen) *outlen = 0;
    return ORDO_SUCCESS;
}

size_t cfb_query(prim_t cipher,
                 int query, size_t value)
{
    switch(query)
    {
        case IV_LEN_Q: return block_query(cipher, BLOCK_SIZE_Q, 0);
        default      : return 0;
    }
}

size_t cfb_bsize(void)
{
    return sizeof(struct CFB_STATE);
}
