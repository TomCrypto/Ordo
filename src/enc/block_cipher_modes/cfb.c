#include <enc/block_cipher_modes/cfb.h>

#include <common/ordo_errors.h>
#include <common/secure_mem.h>
#include <string.h>

/******************************************************************************/

/* This is extra context space required by the CFB mode to store the amount of state not used.*/
struct CFB_STATE
{
    /* A buffer for the IV. */
    void* iv;
    /* The amount of bytes of unused state remaining before the state is to be renewed. */
    size_t remaining;

    int direction;
};

struct CFB_STATE* cfb_alloc(struct BLOCK_CIPHER* cipher, void* cipher_state)
{
    size_t block_size = cipher_block_size(cipher);

    /* Allocate the context and extra buffers in it. */
    struct CFB_STATE* state = secure_alloc(sizeof(struct CFB_STATE));

    if (state)
    {
        if ((state->iv = secure_alloc(block_size)))
        {
            state->remaining = 0;
            return state;
        }

        secure_free(state, sizeof(struct CFB_STATE));
    }

    /* Allocation failed, return zero. */
    return 0;
}

int cfb_init(struct CFB_STATE *state, struct BLOCK_CIPHER* cipher, void* cipher_state, void* iv, int dir, void* params)
{
    size_t block_size = cipher_block_size(cipher);

    state->direction = dir;

    /* Copy the IV (required) into the context IV. */
    memcpy(state->iv, iv, block_size);

    /* Compute the initial keystream block. */
    block_cipher_forward(cipher, cipher_state, state->iv);
    state->remaining = block_size;

    /* Return success. */
    return ORDO_SUCCESS;
}

void cfb_encrypt_update(struct CFB_STATE *state, struct BLOCK_CIPHER* cipher, void* cipher_state, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
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

void cfb_decrypt_update(struct CFB_STATE *state, struct BLOCK_CIPHER* cipher, void* cipher_state, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
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
        memcpy((unsigned char*)state->iv + block_size - state->remaining, in, process);
        state->remaining -= process;
        (*outlen) += process;
        inlen -= process;
        out += process;
        in += process;
    }
}

void cfb_update(struct CFB_STATE *state, struct BLOCK_CIPHER* cipher, void* cipher_state, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
{
    (state->direction
     ? cfb_encrypt_update(state, cipher, cipher_state, in, inlen, out, outlen)
     : cfb_decrypt_update(state, cipher, cipher_state, in, inlen, out, outlen));
}

int cfb_final(struct CFB_STATE *state, struct BLOCK_CIPHER* cipher, void* cipher_state, unsigned char* out, size_t* outlen)
{
    /* Write output size if applicable. */
    if (outlen) *outlen = 0;

    /* Return success. */
    return ORDO_SUCCESS;
}

void cfb_free(struct CFB_STATE *state, struct BLOCK_CIPHER* cipher, void* cipher_state)
{
    /* Free context space. */
    secure_free(state->iv, cipher_block_size(cipher));
    secure_free(state, sizeof(struct CFB_STATE));
}

/* Fills a BLOCK_MODE struct with the correct information. */
void cfb_set_mode(struct BLOCK_MODE* mode)
{
    make_block_mode(mode,
                    (BLOCK_MODE_ALLOC)cfb_alloc,
                    (BLOCK_MODE_INIT)cfb_init,
                    (BLOCK_MODE_UPDATE)cfb_update,
                    (BLOCK_MODE_FINAL)cfb_final,
                    (BLOCK_MODE_FREE)cfb_free,
                    "CFB");
}
