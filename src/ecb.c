/*===-- ecb.c -----------------------------------------*- generic -*- C -*-===*/

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

#include "ordo/primitives/block_modes/ecb.h"

/*===----------------------------------------------------------------------===*/

#if annotation
struct ECB_STATE
{
    unsigned char block[BLOCK_BLOCK_LEN];
    size_t available;

    size_t block_size;

    size_t padding;
    int direction;
};
#endif /* annotation */

/*===----------------------------------------------------------------------===*/

int ecb_init(struct ECB_STATE *state,
             struct BLOCK_STATE *cipher_state,
             const void *iv, size_t iv_len,
             int direction,
             const struct ECB_PARAMS *params)
{
    state->block_size = block_query(cipher_state->primitive, BLOCK_SIZE_Q, 0);

    /* ECB accepts no IV - it is an error to pass it one. Note for consistency
     * only the iv_len parameter is checked - iv itself is in fact ignored. */
    if (ecb_query(cipher_state->primitive, IV_LEN_Q, iv_len) != iv_len)
        return ORDO_ARG;

    state->available = 0;
    state->direction = direction;
    state->padding = (params == 0) ? 1 : (params->padding == 1);

    return ORDO_SUCCESS;
}

void ecb_update(struct ECB_STATE *state,
                struct BLOCK_STATE *cipher_state,
                const void *in, size_t in_len,
                void *out, size_t *out_len)
{
    size_t block_size = state->block_size;

    /* If decrypting, skip the last block if using padding. */
    size_t skip = (state->direction ? 0 : state->padding);

    *out_len = 0;
    if (!in_len) return;

    /* Do we have a partial block to fill in, and not the last
     * block? */

    if (state->available && (state->available + in_len >= block_size + skip))
    {
        /* Add the needed data to the buffer and encrypt/output */
        memcpy(state->block + state->available, in, block_size - state->available);

        if (state->direction)
            block_forward(cipher_state, state->block);
        else
            block_inverse(cipher_state, state->block);

        memcpy(out, state->block, block_size);
        out = offset(out, block_size);
        *out_len += block_size;

        in = offset(in, block_size - state->available);
        in_len -= block_size - state->available;
        state->available = 0;
    }

    /* Now process every block quickly if we have at least 1 block! */

    while (in_len > block_size + skip)
    {
        if (out != in)
            memcpy(out, in, block_size);

        if (state->direction)
            block_forward(cipher_state, out);
        else
            block_inverse(cipher_state, out);

        out = offset(out, block_size);
        *out_len += block_size;

        in = offset(in, block_size);
        in_len -= block_size;
    }

    /* Whatever is left over is saved. */

    memcpy(state->block + state->available, in, in_len);
    state->available += in_len;
}

static int ecb_encrypt_final(struct ECB_STATE *state,
                             struct BLOCK_STATE *cipher_state,
                             void *out, size_t *out_len)
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
        block_forward(cipher_state, state->block);

        memcpy(out, state->block, block_size);
        *out_len = block_size;
    }

    return ORDO_SUCCESS;
}

static int ecb_decrypt_final(struct ECB_STATE *state,
                             struct BLOCK_STATE *cipher_state,
                             void *out, size_t *out_len)
{
    if (!state->padding)
    {
        *out_len = state->available;
        if (*out_len != 0) return ORDO_LEFTOVER;
    }
    else
    {
        size_t msg_length;

        block_inverse(cipher_state, state->block);

        if (!(msg_length = pad_check(state->block, state->block_size)))
        {
            *out_len = 0;
            return ORDO_PADDING;
        }

        memcpy(out, state->block, *out_len = msg_length);
    }

    return ORDO_SUCCESS;
}

int ecb_final(struct ECB_STATE *state,
              struct BLOCK_STATE *cipher_state,
              void *out, size_t *out_len)
{
    return (state->direction
            ? ecb_encrypt_final(state, cipher_state, out, out_len)
            : ecb_decrypt_final(state, cipher_state, out, out_len));
}

size_t ecb_query(prim_t cipher,
                 int query, size_t value)
{
    switch(query)
    {
        case IV_LEN_Q: return 0;

        default: return 0;
    }
}

size_t ecb_bsize(void)
{
    return sizeof(struct ECB_STATE);
}
