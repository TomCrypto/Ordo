#include <enc/block_cipher_modes/ctr.h>

#include <common/errors.h>
#include <common/utils.h>
#include <internal/mem.h>

#include <string.h>

/******************************************************************************/

/* This is extra context space required by the CTR mode to store the counter and the amount of state not used.*/
struct CTR_STATE
{
    /* A buffer for the IV. */
    void* iv;
    /* The counter value. */
    unsigned char* counter;
    /* The amount of bytes of unused state remaining before the state is to be renewed. */
    size_t remaining;
};

struct CTR_STATE* ctr_alloc(const struct BLOCK_CIPHER* cipher, void* cipher_state)
{
    size_t block_size = cipher_block_size(cipher);

    struct CTR_STATE *state = mem_alloc(sizeof(struct CTR_STATE));
    if (!state) goto fail;

    state->iv = mem_alloc(block_size);
    if (!state->iv) goto fail;

    state->counter = mem_alloc(block_size);
    if (!state->counter) goto fail;

    state->remaining = 0;
    return state;

fail:
    ctr_free(state, cipher, cipher_state);
    return 0;
}

int ctr_init(struct CTR_STATE *state, const struct BLOCK_CIPHER* cipher, void* cipher_state, const void* iv, size_t iv_len, int dir, const void* params)
{
    size_t block_size = cipher_block_size(cipher);

    if (iv_len > block_size) return ORDO_ARG;

    /* Copy the IV (required) into the context IV. */
    memset(state->iv, 0x00, block_size);
    memcpy(state->iv, iv, iv_len);

    /* Copy the IV into the counter. */
    memcpy(state->counter, state->iv, block_size);

    /* Compute the initial keystream block. */
    block_cipher_forward(cipher, cipher_state, state->iv);
    state->remaining = block_size;

    return ORDO_SUCCESS;
}

void ctr_update(struct CTR_STATE *state, const struct BLOCK_CIPHER* cipher, void* cipher_state, const unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
{
    /* Variable to store how much data can be processed per iteration. */
    size_t block_size = cipher_block_size(cipher);
    size_t process = 0;

    /* Initialize the output size. */
    *outlen = 0;

    /* Go over the input buffer byte per byte. */
    while (inlen != 0)
    {
        /* If there is no data left in the context block, update. */
        if (state->remaining == 0)
        {
            /* CTR update (increment counter, copy counter into IV, encrypt IV). */
            inc_buffer(state->counter, block_size);
            memcpy(state->iv, state->counter, block_size);
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

int ctr_final(struct CTR_STATE *state, const struct BLOCK_CIPHER* cipher, void* cipher_state, unsigned char* out, size_t* outlen)
{
    if (outlen) *outlen = 0;
    return ORDO_SUCCESS;
}

void ctr_free(struct CTR_STATE *state, const struct BLOCK_CIPHER* cipher, void* cipher_state)
{
    if (!state) return;

    mem_free(state->counter);
    mem_free(state->iv);
    mem_free(state);
}

void ctr_copy(struct CTR_STATE *dst, const struct CTR_STATE *src, const struct BLOCK_CIPHER* cipher)
{
    memcpy(dst->counter, src->counter, cipher_block_size(cipher));
    memcpy(dst->iv, src->iv, cipher_block_size(cipher));
    dst->remaining = src->remaining;
}

void ctr_set_mode(struct BLOCK_MODE* mode)
{
    make_block_mode(mode,
                    (BLOCK_MODE_ALLOC)ctr_alloc,
                    (BLOCK_MODE_INIT)ctr_init,
                    (BLOCK_MODE_UPDATE)ctr_update,
                    (BLOCK_MODE_FINAL)ctr_final,
                    (BLOCK_MODE_FREE)ctr_free,
                    (BLOCK_MODE_COPY)ctr_copy,
                    "CTR");
}
