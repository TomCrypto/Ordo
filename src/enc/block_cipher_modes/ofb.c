#include <enc/block_cipher_modes/ofb.h>

#include <common/ordo_errors.h>
#include <internal/mem.h>

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

    struct OFB_STATE* state = mem_alloc(sizeof(struct OFB_STATE));
    if (!state) goto fail;

    state->iv = mem_alloc(block_size);
    if (!state->iv) goto fail;

    state->remaining = 0;
    return state;

fail:
    ofb_free(state, cipher, cipher_state);
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
    if (outlen) *outlen = 0;
    return ORDO_SUCCESS;
}

void ofb_free(struct OFB_STATE *state, const struct BLOCK_CIPHER* cipher, void* cipher_state)
{
    mem_free(state->iv);
    mem_free(state);
}

void ofb_copy(struct OFB_STATE *dst, const struct OFB_STATE *src, const struct BLOCK_CIPHER* cipher)
{
    memcpy(dst->iv, src->iv, cipher_block_size(cipher));
    dst->remaining = src->remaining;
}

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
