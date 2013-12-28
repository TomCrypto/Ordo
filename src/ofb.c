//===-- ofb.c -----------------------------------------*- generic -*- C -*-===//

#include "ordo/primitives/block_modes/ofb.h"

/// @cond
#include "ordo/internal/implementation.h"
/// @endcond

//===----------------------------------------------------------------------===//

struct OFB_STATE
{
    void *iv;
    size_t remaining; // unused data in the state
    size_t block_size;
};

struct OFB_STATE *ofb_alloc(const struct BLOCK_CIPHER *cipher,
                            const void *cipher_state)
{
    struct OFB_STATE *state = mem_alloc(sizeof(struct OFB_STATE));
    if (!state) goto fail;

    state->block_size = block_cipher_query(cipher, BLOCK_SIZE, 0);

    state->iv = mem_alloc(state->block_size);
    if (!state->iv) goto fail;

    state->remaining = 0;
    return state;

fail:
    ofb_free(state, cipher, cipher_state);
    return 0;
}

int ofb_init(struct OFB_STATE *state,
             const struct BLOCK_CIPHER *cipher,
             const void *cipher_state,
             const void *iv,
             size_t iv_len,
             int dir,
             const void *params)
{
    size_t block_size = state->block_size;

    if (ofb_query(cipher, IV_LEN, iv_len) != iv_len) return ORDO_ARG;

    // Copy the IV (required) into the context IV
    memset(state->iv, 0x00, block_size);
    memcpy(state->iv, iv, iv_len);

    // Compute the initial keystream block
    block_cipher_forward(cipher, cipher_state, state->iv);
    state->remaining = block_size;

    return ORDO_SUCCESS;
}

void ofb_update(struct OFB_STATE *state,
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

        // Is there data left?
        if (state->remaining == 0)
        {
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

int ofb_final(struct OFB_STATE *state,
              const struct BLOCK_CIPHER *cipher,
              const void *cipher_state,
              unsigned char *out,
              size_t *outlen)
{
    if (outlen) *outlen = 0;
    return ORDO_SUCCESS;
}

void ofb_free(struct OFB_STATE *state,
              const struct BLOCK_CIPHER *cipher,
              const void *cipher_state)
{
    if (state) mem_free(state->iv);
    mem_free(state);
}

void ofb_copy(struct OFB_STATE *dst,
              const struct OFB_STATE *src,
              const struct BLOCK_CIPHER *cipher)
{
    memcpy(dst->iv, src->iv, dst->block_size);
    dst->remaining = src->remaining;
}

size_t ofb_query(const struct BLOCK_CIPHER *cipher, int query, size_t value)
{
    switch(query)
    {
        case IV_LEN: return block_cipher_query(cipher, BLOCK_SIZE, 0);
        default    : return 0;
    }
}
