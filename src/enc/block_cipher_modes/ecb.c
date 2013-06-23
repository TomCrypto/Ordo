#include <enc/block_cipher_modes/ecb.h>

#include <common/ordo_errors.h>
#include <common/secure_mem.h>
#include <string.h>

/******************************************************************************/

/* This is extra context space required by the ECB mode to store temporary incomplete data buffers.*/
struct ECB_STATE
{
    /* ,The temporary block, the size of the primitive's block size. */
    unsigned char* block;
    /* The amount of bytes of plaintext or ciphertext currently in the temporary block. */
    size_t available;
    /* Whether to pad the ciphertext. */
    size_t padding;

    int direction;
};

struct ECB_STATE* ecb_alloc(const struct BLOCK_CIPHER *cipher, void* cipher_state)
{
    size_t block_size = cipher_block_size(cipher);

    /* Allocate the context and extra buffers in it. */
    struct ECB_STATE* state = secure_alloc(sizeof(struct ECB_STATE));

    if (state)
    {
        /* Return if everything succeeded. */
        if ((state->block = secure_alloc(block_size)))
        {
            state->available = 0;
            return state;
        }

        /* Clean up if an error occurred. */
        secure_free(state, sizeof(struct ECB_STATE));
    }

    /* Allocation failed, return zero. */
    return 0;
}

int ecb_init(struct ECB_STATE *state, const struct BLOCK_CIPHER *cipher, void* cipher_state, const void* iv, size_t iv_len, int dir, const struct ECB_PARAMS* params)
{
    state->direction = dir;

    /* Check and save the parameters. */
    state->padding = (params == 0) ? 1 : params->padding & 1;

    /* Return success. */
    return ORDO_SUCCESS;
}

void ecb_encrypt_update(struct ECB_STATE *state, const struct BLOCK_CIPHER *cipher, void* cipher_state, const unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
{
    size_t block_size = cipher_block_size(cipher);

    /* Initialize output size. */
    *outlen = 0;

    /* Process all full blocks. */
    while (state->available + inlen >= block_size)
    {
        /* Copy it in, and process it. */
        memcpy(state->block + state->available, in, block_size - state->available);

        /* Encrypt the block. */
        block_cipher_forward(cipher, cipher_state, state->block);

        /* Write back the block to the output. */
        memcpy(out, state->block, block_size);
        *outlen += block_size;
        out += block_size;

        /* Go forward in the input buffer. */
        inlen -= block_size - state->available;
        in += block_size - state->available;
        state->available = 0;
    }

    /* Add whatever is left in the temporary buffer. */
    memcpy(state->block + state->available, in, inlen);
    state->available += inlen;
}

void ecb_decrypt_update(struct ECB_STATE *state, const struct BLOCK_CIPHER *cipher, void* cipher_state, const unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
{
    size_t block_size = cipher_block_size(cipher);

    /* Initialize output size. */
    *outlen = 0;

    /* Process all full blocks except the last potential block (if padding is disabled, also process the last block). */
    while (state->available + inlen > block_size - (1 - state->padding))
    {
        /* Copy it in, and process it. */
        memcpy(state->block + state->available, in, block_size - state->available);

        /* Decrypt the block. */
        block_cipher_inverse(cipher, cipher_state, state->block);

        /* Write back the block to the output. */
        memcpy(out, state->block, block_size);
        *outlen += block_size;
        out += block_size;

        /* Go forward in the input buffer. */
        inlen -= block_size - state->available;
        in += block_size - state->available;
        state->available = 0;
    }

    /* Save the final block. */
    memcpy(state->block + state->available, in, inlen);
    state->available += inlen;
}

int ecb_encrypt_final(struct ECB_STATE *state, const struct BLOCK_CIPHER *cipher, void* cipher_state, unsigned char* out, size_t* outlen)
{
    size_t block_size = cipher_block_size(cipher);
    unsigned char padding;

    /* If padding is disabled, we need to handle things differently. */
    if (state->padding == 0)
    {
        /* If there is data left, return an error and the number of plaintext left in outlen. */
        *outlen = state->available;
        if (*outlen != 0) return ORDO_LEFTOVER;
    }
    else
    {
        /* Compute the amount of padding required. */
        padding = block_size - state->available % block_size;

        /* Write padding to the last block. */
        memset(state->block + state->available, padding, padding);

        /* Encrypt the last block. */
        block_cipher_forward(cipher, cipher_state, state->block);

        /* Write it out to the buffer. */
        memcpy(out, state->block, block_size);
        *outlen = block_size;
    }

    /* Return success. */
    return ORDO_SUCCESS;
}

int ecb_decrypt_final(struct ECB_STATE *state, const struct BLOCK_CIPHER *cipher, void* cipher_state, unsigned char* out, size_t* outlen)
{
    size_t block_size = cipher_block_size(cipher);
    unsigned char padding;

    /* If padding is disabled, we need to handle things differently. */
    if (!state->padding)
    {
        /* If there is data left, return an error and the number of plaintext left in outlen. */
        *outlen = state->available;
        if (*outlen != 0) return ORDO_LEFTOVER;
    }
    else
    {
        /* Otherwise, decrypt the last block. */
        block_cipher_inverse(cipher, cipher_state, state->block);

        /* Read the amount of padding. */
        padding = *(state->block + block_size - 1);

        /* Check the padding. */
        if ((padding != 0) && (padding <= block_size) && (pad_check(state->block + block_size - padding, padding)))
        {
            /* Remove the padding data and output the plaintext. */
            *outlen = block_size - padding;
            memcpy(out, state->block, *outlen);
        }
        else
        {
            *outlen = 0;
            return ORDO_PADDING;
        }
    }

    /* Return success. */
    return ORDO_SUCCESS;
}

void ecb_update(struct ECB_STATE *state, const struct BLOCK_CIPHER *cipher, void* cipher_state, const unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
{
    (state->direction
     ? ecb_encrypt_update(state, cipher, cipher_state, in, inlen, out, outlen)
     : ecb_decrypt_update(state, cipher, cipher_state, in, inlen, out, outlen));
}

int ecb_final(struct ECB_STATE *state, const struct BLOCK_CIPHER *cipher, void* cipher_state, unsigned char* out, size_t* outlen)
{
    return (state->direction
            ? ecb_encrypt_final(state, cipher, cipher_state, out, outlen)
            : ecb_decrypt_final(state, cipher, cipher_state, out, outlen));
}

void ecb_free(struct ECB_STATE *state, const struct BLOCK_CIPHER *cipher, void* cipher_state)
{
    /* Dellocate context fields. */
    secure_free(state->block, cipher_block_size(cipher));
    secure_free(state, sizeof(struct ECB_STATE));
}

void ecb_copy(struct ECB_STATE *dst, const struct ECB_STATE *src, const struct BLOCK_CIPHER* cipher)
{
    memcpy(dst->block, src->block, cipher_block_size(cipher));
    dst->available = src->available;
    dst->direction = src->direction;
    dst->padding = src->padding;
}

/* Fills a BLOCK_MODE struct with the correct information. */
void ecb_set_mode(struct BLOCK_MODE* mode)
{
    make_block_mode(mode,
                    (BLOCK_MODE_ALLOC)ecb_alloc,
                    (BLOCK_MODE_INIT)ecb_init,
                    (BLOCK_MODE_UPDATE)ecb_update,
                    (BLOCK_MODE_FINAL)ecb_final,
                    (BLOCK_MODE_FREE)ecb_free,
                    (BLOCK_MODE_COPY)ecb_copy,
                    "ECB");
}
