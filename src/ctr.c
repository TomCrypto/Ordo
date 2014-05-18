/*===-- ctr.c -----------------------------------------*- generic -*- C -*-===*/

#include "ordo/primitives/block_modes/ctr.h"

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

/*===----------------------------------------------------------------------===*/

/* #if annotation */
struct CTR_STATE
{
    unsigned char iv[2048];
    unsigned char counter[2048];
    size_t remaining;
    size_t block_size;
};
/* #endif /* annotation */

/*===----------------------------------------------------------------------===*/

int ctr_init(struct CTR_STATE *state,
             const struct BLOCK_CIPHER *cipher,
             const void *cipher_state,
             const void *iv,
             size_t iv_len,
             int dir,
             const void *params)
{
    size_t block_size = block_cipher_query(cipher, BLOCK_SIZE_Q, 0);
    state->block_size = block_size;
    state->remaining = 0;

    if (ctr_query(cipher, IV_LEN_Q, iv_len) != iv_len) return ORDO_ARG;

    memset(state->iv, 0x00, block_size);
    memcpy(state->iv, iv, iv_len);
    memcpy(state->counter, state->iv, block_size);

    block_cipher_forward(cipher, cipher_state, state->iv);
    state->remaining = block_size;

    return ORDO_SUCCESS;
}

void ctr_update(struct CTR_STATE *state,
                const struct BLOCK_CIPHER *cipher,
                const void *cipher_state,
                const unsigned char *in,
                size_t inlen,
                unsigned char *out,
                size_t *outlen)
{
    if (outlen) *outlen = 0;

    while (inlen != 0)
    {
        size_t block_size = state->block_size;
        size_t process = 0;

        if (state->remaining == 0)
        {
            inc_buffer(state->counter, block_size);
            memcpy(state->iv, state->counter, block_size);
            block_cipher_forward(cipher, cipher_state, state->iv);
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

int ctr_final(struct CTR_STATE *state,
              const struct BLOCK_CIPHER *cipher,
              const void *cipher_state,
              unsigned char *out,
              size_t *outlen)
{
    if (outlen) *outlen = 0;
    return ORDO_SUCCESS;
}

size_t ctr_query(const struct BLOCK_CIPHER *cipher, int query, size_t value)
{
    switch(query)
    {
        case IV_LEN_Q: return block_cipher_query(cipher, BLOCK_SIZE_Q, 0);
        default      : return 0;
    }
}
