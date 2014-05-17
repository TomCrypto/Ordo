/*===-- cbc.c -----------------------------------------*- generic -*- C -*-===*/

#include "ordo/primitives/block_modes/cbc.h"

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

/*===----------------------------------------------------------------------===*/

struct CBC_STATE
{
    unsigned char iv[2048];
    unsigned char block[2048];
    size_t available;

    size_t block_size;

    size_t padding;
    int direction;
};

int cbc_init(struct CBC_STATE *state,
             const struct BLOCK_CIPHER *cipher,
             const void *cipher_state,
             const void *iv,
             size_t iv_len,
             int dir,
             const struct CBC_PARAMS *params)
{
    state->block_size = block_cipher_query(cipher, BLOCK_SIZE_Q, 0);

    if (cbc_query(cipher, IV_LEN_Q, iv_len) != iv_len) return ORDO_ARG;

    state->available = 0;
    state->direction = dir;

    memset(state->iv, 0x00, state->block_size);
    memcpy(state->iv, iv, iv_len);

    state->padding = (params == 0) ? 1 : params->padding & 1;

    return ORDO_SUCCESS;
}

static void cbc_encrypt_update(struct CBC_STATE *state,
                               const struct BLOCK_CIPHER *cipher,
                               const void *cipher_state,
                               const unsigned char *in,
                               size_t in_len,
                               unsigned char *out,
                               size_t *out_len)
{
    size_t block_size = state->block_size;
    *out_len = 0;

    /* Process all full blocks in the input buffer */
    while (state->available + in_len >= block_size)
    {
        size_t process = block_size - state->available;

        memcpy(state->block + state->available, in, process);

        xor_buffer(state->block, state->iv, block_size);
        block_cipher_forward(cipher, cipher_state, state->block);
        memcpy(state->iv, state->block, block_size);

        memcpy(out, state->block, block_size);
        *out_len += block_size;
        out += block_size;

        state->available = 0;
        in_len -= process;
        in += process;
    }

    /* Add whatever is left into the temporary buffer */
    memcpy(state->block + state->available, in, in_len);
    state->available += in_len;
}

static void cbc_decrypt_update(struct CBC_STATE *state,
                               const struct BLOCK_CIPHER *cipher,
                               const void *cipher_state,
                               const unsigned char *in,
                               size_t in_len,
                               unsigned char *out,
                               size_t *out_len)
{
    size_t block_size = state->block_size;
    *out_len = 0;

    /* If padding is disabled, process all blocks. If it is enabled, don't
     * process the last block (it will be handled in cbc_final). */
    while (state->available + in_len > block_size - (1 - state->padding))
    {
        size_t process = block_size - state->available;

        memcpy(state->block + state->available, in, process);

        /* Save current ciphertext to out, needed since upcoming operations
         * are lossy wrt state. */
        memcpy(out, state->block, block_size);

        block_cipher_inverse(cipher, cipher_state, state->block);
        xor_buffer(state->block, state->iv, block_size);
        memcpy(state->iv, out, block_size);

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

static int cbc_encrypt_final(struct CBC_STATE *state,
                             const struct BLOCK_CIPHER *cipher,
                             const void *cipher_state,
                             unsigned char *out,
                             size_t *out_len)
{
    if (state->padding == 0)
    {
        *out_len = state->available;
        if (*out_len != 0) return ORDO_LEFTOVER;
    }
    else
    {
        size_t block_size = state->block_size;
        uint8_t padding;

        padding = (uint8_t)(block_size - state->available % block_size);

        memset(state->block + state->available, padding, padding);
        xor_buffer(state->block, state->iv, block_size);
        block_cipher_forward(cipher, cipher_state, state->block);

        memcpy(out, state->block, block_size);
        *out_len = block_size;
    }

    return ORDO_SUCCESS;
}

static int cbc_decrypt_final(struct CBC_STATE *state,
                             const struct BLOCK_CIPHER *cipher,
                             const void *cipher_state,
                             unsigned char *out,
                             size_t *out_len)
{
    if (state->padding == 0)
    {
        *out_len = state->available;
        if (*out_len != 0) return ORDO_LEFTOVER;
    }
    else
    {
        size_t block_size = state->block_size;
        uint8_t padding;

        block_cipher_inverse(cipher, cipher_state, state->block);
        xor_buffer(state->block, state->iv, block_size);

        padding = (uint8_t)(*(state->block + block_size - 1));

        if ((padding == 0) || (padding > block_size))
        {
            *out_len = 0;
           return ORDO_PADDING;
        }

        if (pad_check(state->block + block_size - padding, padding))
        {
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

void cbc_update(struct CBC_STATE *state,
                const struct BLOCK_CIPHER *cipher,
                const void *cipher_state,
                const unsigned char *in,
                size_t in_len,
                unsigned char *out,
                size_t *out_len)
{
    (state->direction
     ? cbc_encrypt_update(state, cipher, cipher_state,
                          in, in_len, out, out_len)
     : cbc_decrypt_update(state, cipher, cipher_state,
                          in, in_len, out, out_len));
}

int cbc_final(struct CBC_STATE *state,
              const struct BLOCK_CIPHER *cipher,
              const void *cipher_state,
              unsigned char *out,
              size_t *out_len)
{
    return (state->direction
            ? cbc_encrypt_final(state, cipher, cipher_state, out, out_len)
            : cbc_decrypt_final(state, cipher, cipher_state, out, out_len));
}

size_t cbc_query(const struct BLOCK_CIPHER *cipher, int query, size_t value)
{
    switch(query)
    {
        case IV_LEN_Q: return block_cipher_query(cipher, BLOCK_SIZE_Q, 0);
        default      : return 0;
    }
}
