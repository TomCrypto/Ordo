/*===-- cbc.c -----------------------------------------*- generic -*- C -*-===*/

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

#include "ordo/primitives/block_modes/cbc.h"

/*===----------------------------------------------------------------------===*/

#ifdef OPAQUE
struct CBC_STATE
{
    unsigned char iv[BLOCK_BLOCK_LEN];
    unsigned char block[BLOCK_BLOCK_LEN];
    size_t available;

    size_t block_size;

    size_t padding;
    int direction;
};
#endif

/*===----------------------------------------------------------------------===*/

int cbc_init(struct CBC_STATE *state,
             struct BLOCK_STATE *cipher_state,
             const void *iv, size_t iv_len,
             int dir,
             const struct CBC_PARAMS *params)
{
    int err;

    struct BLOCK_MODE_LIMITS limits;
    struct BLOCK_LIMITS block_lims;

    if ((err = cbc_limits(cipher_state->primitive, &limits)))
        return err;
    if ((err = block_limits(cipher_state->primitive, &block_lims)))
        return err;

    state->block_size = block_lims.block_size;

    if (!limit_check(iv_len, limits.iv_min, limits.iv_max, limits.iv_mul))
        return ORDO_ARG;

    state->available = 0;
    state->direction = dir;

    memset(state->iv, 0x00, state->block_size);
    memcpy(state->iv, iv, iv_len);

    state->padding = (params == 0) ? 1 : (params->padding == 1);

    return ORDO_SUCCESS;
}

static void cbc_encrypt_update(struct CBC_STATE *state,
                               struct BLOCK_STATE *cipher_state,
                               const void *in, size_t in_len,
                               void *out, size_t *out_len)
{
    size_t block_size = state->block_size;
    *out_len = 0;

    /* Process all full blocks in the input buffer */
    while (state->available + in_len >= block_size)
    {
        size_t process = block_size - state->available;

        memcpy(state->block + state->available, in, process);

        xor_buffer(state->block, state->iv, block_size);
        block_forward(cipher_state, state->block);
        memcpy(state->iv, state->block, block_size);

        memcpy(out, state->block, block_size);
        out = offset(out, block_size);
        *out_len += block_size;

        in = offset(in, process);
        state->available = 0;
        in_len -= process;
    }

    /* Add whatever is left into the temporary buffer */
    memcpy(state->block + state->available, in, in_len);
    state->available += in_len;
}

static void cbc_decrypt_update(struct CBC_STATE *state,
                               struct BLOCK_STATE *cipher_state,
                               const void *in, size_t in_len,
                               void *out, size_t *out_len)
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

        block_inverse(cipher_state, state->block);
        xor_buffer(state->block, state->iv, block_size);
        memcpy(state->iv, out, block_size);

        memcpy(out, state->block, block_size);
        out = offset(out, block_size);
        *out_len += block_size;

        in = offset(in, process);
        state->available = 0;
        in_len -= process;
    }

    memcpy(state->block + state->available, in, in_len);
    state->available += in_len;
}

static int cbc_encrypt_final(struct CBC_STATE *state,
                             struct BLOCK_STATE *cipher_state,
                             void *out, size_t *out_len)
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
        block_forward(cipher_state, state->block);

        memcpy(out, state->block, block_size);
        *out_len = block_size;
    }

    return ORDO_SUCCESS;
}

static int cbc_decrypt_final(struct CBC_STATE *state,
                             struct BLOCK_STATE *cipher_state,
                             void *out, size_t *out_len)
{
    if (state->padding == 0)
    {
        *out_len = state->available;
        if (*out_len != 0) return ORDO_LEFTOVER;
    }
    else
    {
        size_t msg_length;

        block_inverse(cipher_state, state->block);
        xor_buffer(state->block, state->iv, state->block_size);

        if (!(msg_length = pad_check(state->block, state->block_size)))
        {
            *out_len = 0;
            return ORDO_PADDING;
        }

        memcpy(out, state->block, *out_len = msg_length);
    }

    return ORDO_SUCCESS;
}

void cbc_update(struct CBC_STATE *state,
                struct BLOCK_STATE *cipher_state,
                const void *in, size_t in_len,
                void *out, size_t *out_len)
{
    (state->direction
     ? cbc_encrypt_update(state, cipher_state,
                          in, in_len, out, out_len)
     : cbc_decrypt_update(state, cipher_state,
                          in, in_len, out, out_len));
}

int cbc_final(struct CBC_STATE *state,
              struct BLOCK_STATE *cipher_state,
              void *out, size_t *out_len)
{
    return (state->direction
            ? cbc_encrypt_final(state, cipher_state, out, out_len)
            : cbc_decrypt_final(state, cipher_state, out, out_len));
}
