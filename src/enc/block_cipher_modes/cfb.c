#include <enc/block_cipher_modes/cfb.h>

#include <common/errors.h>
#include <common/utils.h>
#include <internal/mem.h>

#include <string.h>

/******************************************************************************/

/* This is extra context space required by the CFB mode to store the amount of state not used.*/
struct CFB_STATE
{
    /* A buffer for the IV. */
    void* iv;
    void *tmp;
    /* The amount of bytes of unused state remaining before the state is to be renewed. */
    size_t remaining;

    int direction;
};

struct CFB_STATE* cfb_alloc(const struct BLOCK_CIPHER* cipher, void* cipher_state)
{
    size_t block_size = cipher_block_size(cipher);

    struct CFB_STATE* state = mem_alloc(sizeof(struct CFB_STATE));
    if (!state) goto fail;

    state->iv = mem_alloc(block_size);
    if (!state->iv) goto fail;

    state->tmp = mem_alloc(block_size);
    if (!state->tmp) goto fail;

    state->remaining = 0;
    return state;

fail:
    cfb_free(state, cipher, cipher_state);
    return 0;
}

int cfb_init(struct CFB_STATE *state, const struct BLOCK_CIPHER* cipher, void* cipher_state, const void* iv, size_t iv_len, int dir, const void* params)
{
    size_t block_size = cipher_block_size(cipher);

    if (iv_len > block_size) return ORDO_ARG;

    state->direction = dir;

    /* Copy the IV (required) into the context IV. */
    memset(state->iv, 0x00, block_size);
    memcpy(state->iv, iv, iv_len);

    /* Compute the initial keystream block. */
    block_cipher_forward(cipher, cipher_state, state->iv);
    state->remaining = block_size;

    return ORDO_SUCCESS;
}

void cfb_encrypt_update(struct CFB_STATE *state, const struct BLOCK_CIPHER* cipher, void* cipher_state, const unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
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
            /* CFB update (simply apply the permutation function again). */
            block_cipher_forward(cipher, cipher_state, state->iv);
            state->remaining = block_size;
        }

        /* Compute the amount of data to process. */
        process = (inlen < state->remaining) ? inlen : state->remaining;

        /* Process this amount of data. */
        if (out != in) memcpy(out, in, process);
        xor_buffer(out, (unsigned char*)state->iv + block_size - state->remaining, process);
        memcpy((unsigned char*)state->iv + block_size - state->remaining, out, process);
        state->remaining -= process;
        (*outlen) += process;
        inlen -= process;
        out += process;
        in += process;
    }
}

void cfb_decrypt_update(struct CFB_STATE *state, const struct BLOCK_CIPHER* cipher, void* cipher_state, const unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
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
            /* CFB update (simply apply the permutation function again). */
            block_cipher_forward(cipher, cipher_state, state->iv);
            state->remaining = block_size;
        }

        /* Compute the amount of data to process. */
        process = (inlen < state->remaining) ? inlen : state->remaining;

        /* Process this amount of data. */
        if (out != in) memcpy(out, in, process);
        memcpy(state->tmp, in, process);
        xor_buffer(out, (unsigned char*)state->iv + block_size - state->remaining, process);
        memcpy((unsigned char*)state->iv + block_size - state->remaining, state->tmp, process);
        state->remaining -= process;
        (*outlen) += process;
        inlen -= process;
        out += process;
        in += process;
    }
}

void cfb_update(struct CFB_STATE *state, const struct BLOCK_CIPHER* cipher, void* cipher_state, const unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
{
    (state->direction
     ? cfb_encrypt_update(state, cipher, cipher_state, in, inlen, out, outlen)
     : cfb_decrypt_update(state, cipher, cipher_state, in, inlen, out, outlen));
}

int cfb_final(struct CFB_STATE *state, const struct BLOCK_CIPHER* cipher, void* cipher_state, unsigned char* out, size_t* outlen)
{
    if (outlen) *outlen = 0;
    return ORDO_SUCCESS;
}

void cfb_free(struct CFB_STATE *state, const struct BLOCK_CIPHER* cipher, void* cipher_state)
{
    if (!state) return;

    mem_free(state->tmp);
    mem_free(state->iv);
    mem_free(state);
}

void cfb_copy(struct CFB_STATE *dst, const struct CFB_STATE *src, const struct BLOCK_CIPHER* cipher)
{
    memcpy(dst->tmp, src->tmp, cipher_block_size(cipher));
    memcpy(dst->iv, src->iv, cipher_block_size(cipher));
    dst->remaining = src->remaining;
    dst->direction = src->direction;
}

void cfb_set_mode(struct BLOCK_MODE* mode)
{
    make_block_mode(mode,
                    (BLOCK_MODE_ALLOC)cfb_alloc,
                    (BLOCK_MODE_INIT)cfb_init,
                    (BLOCK_MODE_UPDATE)cfb_update,
                    (BLOCK_MODE_FINAL)cfb_final,
                    (BLOCK_MODE_FREE)cfb_free,
                    (BLOCK_MODE_COPY)cfb_copy,
                    "CFB");
}
