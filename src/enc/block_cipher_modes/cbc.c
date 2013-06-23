#include <enc/block_cipher_modes/cbc.h>

#include <common/ordo_errors.h>
#include <common/secure_mem.h>
#include <string.h>

/******************************************************************************/

/* This is extra context space required by the CBC state to store temporary incomplete data buffers.*/
struct CBC_STATE
{
    /* A buffer for the IV. */
    void* iv;
    /* The temporary block, the size of the primitive's block size. */
    unsigned char* block;
    /* The amount of bytes of plaintext or ciphertext currently in the temporary block. */
    size_t available;
    /* Whether to pad the ciphertext. */
    size_t padding;

    int direction;
};

struct CBC_STATE* cbc_alloc(const struct BLOCK_CIPHER* cipher, void* cipher_state)
{
    size_t block_size = cipher_block_size(cipher);

    /* Allocate the context and extra buffers in it. */
    struct CBC_STATE *state = secure_alloc(sizeof(struct CBC_STATE));

    if (state)
    {
        /* Allocate extra buffers for the running IV and temporary block. */
        state->iv = secure_alloc(block_size);
        state->block = secure_alloc(block_size);

        /* Return if every allocation succeeded. */
        if ((state->iv) && (state->block))
        {
            state->available = 0;
            return state;
        }

        /* Clean up if an error occurred. */
        secure_free(state->block, block_size);
        secure_free(state->iv, block_size);
        secure_free(state, sizeof(struct CBC_STATE));
    }

    /* Allocation failed, return zero. */
    return 0;
}

int cbc_init(struct CBC_STATE *state, const struct BLOCK_CIPHER* cipher, void* cipher_state, const void* iv, size_t iv_len, int dir, const struct CBC_PARAMS* params)
{
    if (iv_len > cipher_block_size(cipher)) return ORDO_ARG;

    state->direction = dir;

    /* Copy the IV (required) into the context IV. */
    memset(state->iv, 0x00, cipher_block_size(cipher));
    memcpy(state->iv, iv, iv_len);

    /* Check and save the parameters. */
    state->padding = (params == 0) ? 1 : params->padding & 1;

    /* Return success. */
    return ORDO_SUCCESS;
}

void cbc_encrypt_update(struct CBC_STATE *state, const struct BLOCK_CIPHER* cipher, void* cipher_state, const unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
{
    size_t block_size = cipher_block_size(cipher);

    /* Initialize output size. */
    *outlen = 0;

    /* Process all full blocks. */
    while (state->available + inlen >= block_size)
    {
        /* Copy it in, and process it. */
        memcpy(state->block + state->available, in, block_size - state->available);

        /* Exclusive-or the plaintext block with the running IV. */
        xor_buffer(state->block, state->iv, block_size);

        /* Encrypt the block. */
        block_cipher_forward(cipher, cipher_state, state->block);

        /* Set this as the new running IV. */
        memcpy(state->iv, state->block, block_size);

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

void cbc_decrypt_update(struct CBC_STATE *state, const struct BLOCK_CIPHER* cipher, void* cipher_state, const unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
{
    size_t block_size = cipher_block_size(cipher);

    /* Initialize output size. */
    *outlen = 0;

    /* Process all full blocks except the last potential block (if padding is disabled, also process the last block). */
    while (state->available + inlen > block_size - (1 - state->padding))
    {
        /* Copy it in, and process it. */
        memcpy(state->block + state->available, in, block_size - state->available);

        /* Save this ciphertext block. */
        memcpy(out, state->block, block_size);

        /* Decrypt the block. */
        block_cipher_inverse(cipher, cipher_state, state->block);

        /* Exclusive-or the block with the running IV. */
        xor_buffer(state->block, state->iv, block_size);

        /* Get the original ciphertext back as running IV. */
        memcpy(state->iv, out, block_size);

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

int cbc_encrypt_final(struct CBC_STATE *state, const struct BLOCK_CIPHER* cipher, void* cipher_state, unsigned char* out, size_t* outlen)
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

        /* Exclusive-or the last block with the running IV. */
        xor_buffer(state->block, state->iv, block_size);

        /* Encrypt the last block. */
        block_cipher_forward(cipher, cipher_state, state->block);

        /* Write it out to the buffer. */
        memcpy(out, state->block, block_size);
        *outlen = block_size;
    }

    /* Return success. */
    return ORDO_SUCCESS;
}

int cbc_decrypt_final(struct CBC_STATE *state, const struct BLOCK_CIPHER* cipher, void* cipher_state, unsigned char* out, size_t* outlen)
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

        /* Exclusive-or the last block with the running IV. */
        xor_buffer(state->block, state->iv, block_size);

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

void cbc_update(struct CBC_STATE *state, const struct BLOCK_CIPHER* cipher, void* cipher_state, const unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
{
    (state->direction
     ? cbc_encrypt_update(state, cipher, cipher_state, in, inlen, out, outlen)
     : cbc_decrypt_update(state, cipher, cipher_state, in, inlen, out, outlen));
}

int cbc_final(struct CBC_STATE *state, const struct BLOCK_CIPHER* cipher, void* cipher_state, unsigned char* out, size_t* outlen)
{
    return (state->direction
            ? cbc_encrypt_final(state, cipher, cipher_state, out, outlen)
            : cbc_decrypt_final(state, cipher, cipher_state, out, outlen));
}

void cbc_free(struct CBC_STATE *state, const struct BLOCK_CIPHER* cipher, void* cipher_state)
{
    /* Deallocate context fields. */
    secure_free(state->block, cipher_block_size(cipher));
    secure_free(state->iv, cipher_block_size(cipher));
    secure_free(state, sizeof(struct CBC_STATE));
}

void cbc_copy(struct CBC_STATE *dst, const struct CBC_STATE *src, const struct BLOCK_CIPHER* cipher)
{
    memcpy(dst->block, src->block, cipher_block_size(cipher));
    memcpy(dst->iv, src->iv, cipher_block_size(cipher));
    dst->available = src->available;
    dst->padding = src->padding;
}

/* Fills a BLOCK_MODE struct with the correct information. */
void cbc_set_mode(struct BLOCK_MODE* mode)
{
    make_block_mode(mode,
                    (BLOCK_MODE_ALLOC)cbc_alloc,
                    (BLOCK_MODE_INIT)cbc_init,
                    (BLOCK_MODE_UPDATE)cbc_update,
                    (BLOCK_MODE_FINAL)cbc_final,
                    (BLOCK_MODE_FREE)cbc_free,
                    (BLOCK_MODE_COPY)cbc_copy,
                    "CBC");
}
