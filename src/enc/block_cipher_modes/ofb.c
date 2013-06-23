#include <enc/block_cipher_modes/ofb.h>

#include <common/ordo_errors.h>
#include <common/secure_mem.h>
#include <string.h>

/******************************************************************************/

/* This is extra context space required by the OFB mode to store the amount of state not used.*/
struct OFB_STATE
{
    /* A buffer for the IV. */
    void* iv;
    /* The amount of bytes of unused state remaining before the state is to be renewed. */
    size_t remaining;
};

struct OFB_STATE* ofb_alloc(const struct BLOCK_CIPHER* cipher, void* cipher_state)
{
    size_t block_size = cipher_block_size(cipher);

    /* Allocate the context and extra buffers in it. */
    struct OFB_STATE* state = secure_alloc(sizeof(struct OFB_STATE));

    if (state)
    {
        /* Return if everything succeeded. */
        if ((state->iv = secure_alloc(block_size)))
        {
            state->remaining = 0;
            return state;
        }

        /* Clean up if an error occurred. */
        secure_free(state, sizeof(struct OFB_STATE));
    }

    /* Allocation failed, return zero. */
    return 0;
}

int ofb_init(struct OFB_STATE *state, const struct BLOCK_CIPHER* cipher, void* cipher_state, const void* iv, size_t iv_len, int dir, const void* params)
{
    size_t block_size = cipher_block_size(cipher);

    if (iv_len > block_size) return ORDO_ARG;

    /* Copy the IV (required) into the context IV. */
    memset(state->iv, 0x00, block_size);
    memcpy(state->iv, iv, iv_len);

    /* Compute the initial keystream block. */
    block_cipher_forward(cipher, cipher_state, state->iv);
    state->remaining = block_size;

    /* Return success. */
    return ORDO_SUCCESS;
}

void ofb_update(struct OFB_STATE *state, const struct BLOCK_CIPHER* cipher, void* cipher_state, const unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
{
    /* Variable to store how much data can be processed per iteration. */
    size_t block_size = cipher_block_size(cipher);
    size_t process = 0;

    /* Initialize the output size. */
    *outlen = 0;

    /* Go over the buffer byte per byte. */
    while (inlen != 0)
    {
        /* If there is no data left in the context block, update. */
        if (state->remaining == 0)
        {
            /* OFB update (simply apply the permutation function again). */
            block_cipher_forward(cipher, cipher_state, state->iv);
            state->remaining = block_size;
        }

        /* Compute the amount of data to process. */
        process = (inlen < state->remaining) ? inlen : state->remaining;

        /* Process this amount of data. */
        if (out != in) memcpy(out, in, process);
        xor_buffer(out, (unsigned char*)state->iv + block_size - state->remaining, process);
        state->remaining -= process;
        (*outlen) += process;
        inlen -= process;
        out += process;
        in += process;
    }
}

int ofb_final(struct OFB_STATE *state, const struct BLOCK_CIPHER* cipher, void* cipher_state, unsigned char* out, size_t* outlen)
{
    /* Write output size if applicable. */
    if (outlen) *outlen = 0;

    /* Return success. */
    return ORDO_SUCCESS;
}

void ofb_free(struct OFB_STATE *state, const struct BLOCK_CIPHER* cipher, void* cipher_state)
{
    /* Free context space. */
    secure_free(state->iv, cipher_block_size(cipher));
    secure_free(state, sizeof(struct OFB_STATE));
}

void ofb_copy(struct OFB_STATE *dst, const struct OFB_STATE *src, const struct BLOCK_CIPHER* cipher)
{
    memcpy(dst->iv, src->iv, cipher_block_size(cipher));
    dst->remaining = src->remaining;
}

/* Fills a BLOCK_MODE struct with the correct information. */
void ofb_set_mode(struct BLOCK_MODE* mode)
{
    make_block_mode(mode,
                    (BLOCK_MODE_ALLOC)ofb_alloc,
                    (BLOCK_MODE_INIT)ofb_init,
                    (BLOCK_MODE_UPDATE)ofb_update,
                    (BLOCK_MODE_FINAL)ofb_final,
                    (BLOCK_MODE_FREE)ofb_free,
                    (BLOCK_MODE_COPY)ofb_copy,
                    "OFB");
}
