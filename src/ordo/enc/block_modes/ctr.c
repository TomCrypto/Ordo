#include "ordo/enc/block_modes/ctr.h"

#include "ordo/internal/mem.h"
#include "ordo/common/utils.h"

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
    
    size_t block_size;
};

struct CTR_STATE * ORDO_CALLCONV
ctr_alloc(const struct BLOCK_CIPHER* cipher, void* cipher_state)
{
    struct CTR_STATE *state = mem_alloc(sizeof(struct CTR_STATE));
    if (!state) goto fail;
    
    state->block_size = block_cipher_query(cipher, BLOCK_SIZE, 0);

    state->iv = mem_alloc(state->block_size);
    if (!state->iv) goto fail;

    state->counter = mem_alloc(state->block_size);
    if (!state->counter) goto fail;

    state->remaining = 0;
    return state;

fail:
    ctr_free(state, cipher, cipher_state);
    return 0;
}

int ORDO_CALLCONV
ctr_init(struct CTR_STATE *state,
         const struct BLOCK_CIPHER *cipher,
         void *cipher_state,
         const void *iv,
         size_t iv_len,
         int dir,
         const void *params)
{
    size_t block_size = state->block_size;

    if (ctr_query(cipher, IV_LEN, iv_len) != iv_len) return ORDO_ARG;

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

void ORDO_CALLCONV
ctr_update(struct CTR_STATE *state,
           const struct BLOCK_CIPHER *cipher,
           void *cipher_state,
           const unsigned char *in,
           size_t inlen,
           unsigned char *out,
           size_t *outlen)
{
    /* Variable to store how much data can be processed per iteration. */
    size_t block_size = state->block_size;
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

int ORDO_CALLCONV
ctr_final(struct CTR_STATE *state,
          const struct BLOCK_CIPHER *cipher,
          void *cipher_state,
          unsigned char *out,
          size_t *outlen)
{
    if (outlen) *outlen = 0;
    return ORDO_SUCCESS;
}

void ORDO_CALLCONV
ctr_free(struct CTR_STATE *state,
         const struct BLOCK_CIPHER *cipher,
         void *cipher_state)
{
    if (!state) return;

    mem_free(state->counter);
    mem_free(state->iv);
    mem_free(state);
}

void ORDO_CALLCONV
ctr_copy(struct CTR_STATE *dst,
         const struct CTR_STATE *src,
         const struct BLOCK_CIPHER *cipher)
{
    memcpy(dst->counter, src->counter, dst->block_size);
    memcpy(dst->iv, src->iv, dst->block_size);
    dst->remaining = src->remaining;
}

size_t ORDO_CALLCONV
ctr_query(const struct BLOCK_CIPHER *cipher, int query, size_t value)
{
    switch(query)
    {
        case IV_LEN: return block_cipher_query(cipher, BLOCK_SIZE, 0);
        
        default: return 0;
    }
}
