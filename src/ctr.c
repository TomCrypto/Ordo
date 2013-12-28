//===-- ctr.c -----------------------------------------*- generic -*- C -*-===//

#include "ordo/primitives/block_modes/ctr.h"

/// @cond
#include "ordo/internal/implementation.h"
/// @endcond

//===----------------------------------------------------------------------===//

struct CTR_STATE
{
    void *iv;
    unsigned char *counter;
    size_t remaining;
    size_t block_size;
};

struct CTR_STATE *ctr_alloc(const struct BLOCK_CIPHER *cipher,
                            const void *cipher_state)
{
    struct CTR_STATE *state = mem_alloc(sizeof(struct CTR_STATE));
    if (!state) goto fail;

    state->block_size = block_cipher_query(cipher, BLOCK_SIZE, 0);

    state->iv = mem_alloc(state->block_size);
    if (!state->iv) goto fail;

    state->counter = mem_alloc(state->block_size);
    if (!state->counter) goto fail;

    state->remaining = 0;
    return state;

fail:
    ctr_free(state, cipher, cipher_state);
    return 0;
}

int ctr_init(struct CTR_STATE *state,
             const struct BLOCK_CIPHER *cipher,
             const void *cipher_state,
             const void *iv,
             size_t iv_len,
             int dir,
             const void *params)
{
    size_t block_size = state->block_size;

    if (ctr_query(cipher, IV_LEN, iv_len) != iv_len) return ORDO_ARG;

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
    *outlen = 0;

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
        state->remaining -= process;
        (*outlen) += process;
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

void ctr_free(struct CTR_STATE *state,
              const struct BLOCK_CIPHER *cipher,
              const void *cipher_state)
{
    if (state)
    {
        mem_free(state->counter);
        mem_free(state->iv);
    }

    mem_free(state);
}

void ctr_copy(struct CTR_STATE *dst,
              const struct CTR_STATE *src,
              const struct BLOCK_CIPHER *cipher)
{
    memcpy(dst->counter, src->counter, dst->block_size);
    memcpy(dst->iv, src->iv, dst->block_size);
    dst->remaining = src->remaining;
}

size_t ctr_query(const struct BLOCK_CIPHER *cipher, int query, size_t value)
{
    switch(query)
    {
        case IV_LEN: return block_cipher_query(cipher, BLOCK_SIZE, 0);
        default    : return 0;
    }
}
