/*===-- ecb.c -----------------------------------------*- generic -*- C -*-===*/

#include "ordo/primitives/block_modes/ecb.h"

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

/*===----------------------------------------------------------------------===*/

struct ECB_STATE
{
    unsigned char block[2048];
    size_t available;

    size_t block_size;

    size_t padding;
    int direction;
};

int ecb_init(struct ECB_STATE *state,
             const struct BLOCK_CIPHER *cipher,
             const void *cipher_state,
             const void *iv,
             size_t iv_len,
             int direction,
             const struct ECB_PARAMS *params)
{
    state->block_size = block_cipher_query(cipher, BLOCK_SIZE_Q, 0);

    /* ECB accepts no IV - it is an error to pass it one. Note for consistency
     * only the iv_len parameter is checked - iv itself is in fact ignored. */
    if (ecb_query(cipher, IV_LEN_Q, iv_len) != iv_len) return ORDO_ARG;

    state->available = 0;
    state->direction = direction;
    state->padding = (params == 0) ? 1 : params->padding & 1;

    return ORDO_SUCCESS;
}

void ecb_update(struct ECB_STATE *state,
                const struct BLOCK_CIPHER *cipher,
                const void *cipher_state,
                const unsigned char *in,
                size_t in_len,
                unsigned char *out,
                size_t *out_len)
{
    size_t block_size = state->block_size;

    /* If decrypting, skip the last block if using padding. */
    size_t skip = (state->direction ? 0 : state->padding);

    *out_len = 0;

    while (state->available + in_len >= block_size + skip)
    {
        size_t process = block_size - state->available;

        memcpy(state->block + state->available, in, process);

        if (state->direction)
        {
            block_cipher_forward(cipher, cipher_state, state->block);
        }
        else
        {
            block_cipher_inverse(cipher, cipher_state, state->block);
        }

        memcpy(out, state->block, block_size);
        *out_len += block_size;
        out += block_size;

        state->available = 0;
        in_len -= process;
        in += process;
    }

    memcpy(state->block + state->available, in, in_len);
    state->available += in_len;
}

static int ecb_encrypt_final(struct ECB_STATE *state,
                             const struct BLOCK_CIPHER *cipher,
                             const void *cipher_state,
                             unsigned char *out,
                             size_t *out_len)
{
    if (state->padding == 0)
    {
        /* Return the number of leftover bytes for the user's consideration. */
        *out_len = state->available;
        if (*out_len != 0) return ORDO_LEFTOVER;
    }
    else
    {
        size_t block_size = state->block_size;
        uint8_t padding;

        /* Calculate how many padding bytes are required. We assert here
         * that 0 < block_size < 256, as per standard PKCS padding... */
        padding = (uint8_t)(block_size - state->available % block_size);

        memset(state->block + state->available, padding, padding);
        block_cipher_forward(cipher, cipher_state, state->block);

        memcpy(out, state->block, block_size);
        *out_len = block_size;
    }

    return ORDO_SUCCESS;
}

static int ecb_decrypt_final(struct ECB_STATE *state,
                             const struct BLOCK_CIPHER *cipher,
                             const void *cipher_state,
                             unsigned char *out,
                             size_t *out_len)
{
    if (!state->padding)
    {
        *out_len = state->available;
        if (*out_len != 0) return ORDO_LEFTOVER;
    }
    else
    {
        size_t block_size = state->block_size;
        uint8_t padding;

        block_cipher_inverse(cipher, cipher_state, state->block);

        /* Fetch the padding byte at the end of the block, and verify. */
        padding = (uint8_t)(*(state->block + block_size - 1));

        /* Padding is clearly invalid - reject it immediately. */
        if ((padding == 0) || (padding > block_size))
        {
            *out_len = 0;
            return ORDO_PADDING;
        }

        if (pad_check(state->block + block_size - padding, padding))
        {
            /* Strip off the padding. */
            *out_len = block_size - padding;
            memcpy(out, state->block, *out_len);
        }
        else
        {
            *out_len = 0;
            return ORDO_PADDING;
        }
    }

    return ORDO_SUCCESS;
}

int ecb_final(struct ECB_STATE *state,
              const struct BLOCK_CIPHER *cipher,
              const void *cipher_state,
              unsigned char *out,
              size_t *out_len)
{
    return (state->direction
            ? ecb_encrypt_final(state, cipher, cipher_state, out, out_len)
            : ecb_decrypt_final(state, cipher, cipher_state, out, out_len));
}

size_t ecb_query(const struct BLOCK_CIPHER *cipher, int query, size_t value)
{
    switch(query)
    {
        case IV_LEN_Q: return 0;

        default: return 0;
    }
}
