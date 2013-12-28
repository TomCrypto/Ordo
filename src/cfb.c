//===-- cfb.c -----------------------------------------*- generic -*- C -*-===//

#include "ordo/primitives/block_modes/cfb.h"

/// @cond
#include "ordo/internal/implementation.h"
/// @endcond

//===----------------------------------------------------------------------===//

struct CFB_STATE
{
    void *iv;
    void *tmp;
    size_t remaining;
    size_t block_size;
    int direction;
};

struct CFB_STATE *cfb_alloc(const struct BLOCK_CIPHER *cipher,
                            const void *cipher_state)
{
    struct CFB_STATE *state = mem_alloc(sizeof(struct CFB_STATE));
    if (!state) goto fail;

    state->block_size = block_cipher_query(cipher, BLOCK_SIZE, 0);

    state->iv = mem_alloc(state->block_size);
    if (!state->iv) goto fail;

    state->tmp = mem_alloc(state->block_size);
    if (!state->tmp) goto fail;

    state->remaining = 0;
    return state;

fail:
    cfb_free(state, cipher, cipher_state);
    return 0;
}

int cfb_init(struct CFB_STATE *state,
             const struct BLOCK_CIPHER *cipher,
             const void *cipher_state,
             const void *iv,
             size_t iv_len,
             int dir,
             const void *params)
{
    size_t block_size = state->block_size;

    if (cfb_query(cipher, IV_LEN, iv_len) != iv_len) return ORDO_ARG;

    state->direction = dir;

    memset(state->iv, 0x00, block_size);
    memcpy(state->iv, iv, iv_len);

    block_cipher_forward(cipher, cipher_state, state->iv);
    state->remaining = block_size;

    return ORDO_SUCCESS;
}

static void cfb_encrypt_update(struct CFB_STATE *state,
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
            block_cipher_forward(cipher, cipher_state, state->iv);
            state->remaining = block_size;
        }

        process = (inlen < state->remaining) ? inlen : state->remaining;

        if (out != in) memcpy(out, in, process);
        xor_buffer(out, offset(state->iv, block_size - state->remaining), process);
        memcpy(offset(state->iv, block_size - state->remaining), out, process);
        state->remaining -= process;
        (*outlen) += process;
        inlen -= process;
        out += process;
        in += process;
    }
}

static void cfb_decrypt_update(struct CFB_STATE *state,
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
            block_cipher_forward(cipher, cipher_state, state->iv);
            state->remaining = block_size;
        }

        process = (inlen < state->remaining) ? inlen : state->remaining;

        if (out != in) memcpy(out, in, process);
        memcpy(state->tmp, in, process);
        xor_buffer(out, offset(state->iv, block_size - state->remaining), process);
        memcpy(offset(state->iv, block_size - state->remaining), state->tmp, process);
        state->remaining -= process;
        (*outlen) += process;
        inlen -= process;
        out += process;
        in += process;
    }
}

void cfb_update(struct CFB_STATE *state,
                const struct BLOCK_CIPHER *cipher,
                const void *cipher_state,
                const unsigned char *in,
                size_t inlen,
                unsigned char *out,
                size_t *outlen)
{
    (state->direction
     ? cfb_encrypt_update(state, cipher, cipher_state, in, inlen, out, outlen)
     : cfb_decrypt_update(state, cipher, cipher_state, in, inlen, out, outlen));
}

int cfb_final(struct CFB_STATE *state,
              const struct BLOCK_CIPHER *cipher,
              const void *cipher_state,
              unsigned char *out,
              size_t *outlen)
{
    if (outlen) *outlen = 0;
    return ORDO_SUCCESS;
}

void cfb_free(struct CFB_STATE *state,
              const struct BLOCK_CIPHER *cipher,
              const void *cipher_state)
{
    if (state)
    {
        mem_free(state->tmp);
        mem_free(state->iv);
    }

    mem_free(state);
}

void cfb_copy(struct CFB_STATE *dst,
              const struct CFB_STATE *src,
              const struct BLOCK_CIPHER *cipher)
{
    memcpy(dst->tmp, src->tmp, dst->block_size);
    memcpy(dst->iv, src->iv, dst->block_size);
    dst->remaining = src->remaining;
    dst->direction = src->direction;
}

size_t cfb_query(const struct BLOCK_CIPHER *cipher,
                 int query, size_t value)
{
    switch(query)
    {
        case IV_LEN: return block_cipher_query(cipher, BLOCK_SIZE, 0);
        default    : return 0;
    }
}
