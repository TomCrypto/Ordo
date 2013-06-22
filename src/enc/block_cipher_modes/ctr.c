#include <enc/block_cipher_modes/ctr.h>

#include <common/ordo_errors.h>
#include <common/secure_mem.h>
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

struct CTR_STATE* ctr_alloc(struct BLOCK_CIPHER* cipher, void* cipher_state)
{
    size_t block_size = cipher_block_size(cipher);

    /* Allocate the context and extra buffers in it. */
    struct CTR_STATE *state = secure_alloc(sizeof(struct CTR_STATE));

    if (state)
    {
        /* Allocate extra buffers for the IV and counter. */
        state->iv = secure_alloc(block_size);
        state->counter = secure_alloc(block_size);

        /* Return if everything succeeded. */
        if ((state->iv) && (state->counter))
        {
            state->remaining = 0;
            return state;
        }

        /* Clean up if an error occurred. */
        secure_free(state->counter, block_size);
        secure_free(state->iv, block_size);
        secure_free(state, sizeof(struct CTR_STATE));
    }

    /* Allocation failed, return zero. */
    return 0;
}

int ctr_init(struct CTR_STATE *state, struct BLOCK_CIPHER* cipher, void* cipher_state, void* iv, int dir, void* params)
{
    size_t block_size = cipher_block_size(cipher);

    /* Copy the IV (required) into the context IV. */
    memcpy(state->iv, iv, block_size);

    /* Copy the IV into the counter. */
    memcpy(state->counter, state->iv, block_size);

    /* Compute the initial keystream block. */
	block_cipher_forward(cipher, cipher_state, state->iv);
    state->remaining = block_size;

    /* Return success. */
    return ORDO_SUCCESS;
}

void ctr_update(struct CTR_STATE *state, struct BLOCK_CIPHER* cipher, void* cipher_state, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
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

int ctr_final(struct CTR_STATE *state, struct BLOCK_CIPHER* cipher, void* cipher_state, unsigned char* out, size_t* outlen)
{
    /* Write output size if applicable. */
    if (outlen) *outlen = 0;

    /* Return success. */
    return ORDO_SUCCESS;
}

void ctr_free(struct CTR_STATE *state, struct BLOCK_CIPHER* cipher, void* cipher_state)
{
    /* Free context space. */
    secure_free(state->counter, cipher_block_size(cipher));
    secure_free(state->iv, cipher_block_size(cipher));
    secure_free(state, sizeof(struct CTR_STATE));
}

/* Fills a BLOCK_MODE struct with the correct information. */
void ctr_set_mode(struct BLOCK_MODE* mode)
{
    make_block_mode(mode,
                    (BLOCK_MODE_ALLOC)ctr_alloc,
                    (BLOCK_MODE_INIT)ctr_init,
                    (BLOCK_MODE_UPDATE)ctr_update,
                    (BLOCK_MODE_FINAL)ctr_final,
                    (BLOCK_MODE_FREE)ctr_free,
                    "CTR");
}
