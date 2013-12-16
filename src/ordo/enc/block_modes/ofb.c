#include "ordo/enc/block_modes/ofb.h"

#include "ordo/internal/mem.h"
#include "ordo/common/utils.h"

#include <string.h>

/******************************************************************************/

/* This is extra context space required by the OFB mode to store the amount of state not used.*/
struct OFB_STATE
{
    /* A buffer for the IV. */
    void* iv;
    /* The amount of bytes of unused state remaining before the state is to be renewed. */
    size_t remaining;
    
    size_t block_size;
};

struct OFB_STATE * ORDO_CALLCONV
ofb_alloc(const struct BLOCK_CIPHER* cipher, void* cipher_state)
{
    struct OFB_STATE* state = mem_alloc(sizeof(struct OFB_STATE));
    if (!state) goto fail;
    
    state->block_size = block_cipher_query(cipher, BLOCK_SIZE, 0);

    state->iv = mem_alloc(state->block_size);
    if (!state->iv) goto fail;

    state->remaining = 0;
    return state;

fail:
    ofb_free(state, cipher, cipher_state);
    return 0;
}

int ORDO_CALLCONV
ofb_init(struct OFB_STATE *state,
         const struct BLOCK_CIPHER *cipher,
         void *cipher_state,
         const void *iv,
         size_t iv_len,
         int dir,
         const void *params)
{
    size_t block_size = state->block_size;

    if (ofb_query(cipher, IV_LEN, iv_len) != iv_len) return ORDO_ARG;

    /* Copy the IV (required) into the context IV. */
    memset(state->iv, 0x00, block_size);
    memcpy(state->iv, iv, iv_len);

    /* Compute the initial keystream block. */
    block_cipher_forward(cipher, cipher_state, state->iv);
    state->remaining = block_size;

    return ORDO_SUCCESS;
}

void ORDO_CALLCONV
ofb_update(struct OFB_STATE *state,
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

int ORDO_CALLCONV
ofb_final(struct OFB_STATE *state,
          const struct BLOCK_CIPHER *cipher,
          void *cipher_state,
          unsigned char *out,
          size_t *outlen)
{
    if (outlen) *outlen = 0;
    return ORDO_SUCCESS;
}

void ORDO_CALLCONV
ofb_free(struct OFB_STATE *state,
         const struct BLOCK_CIPHER *cipher,
         void *cipher_state)
{
    if (!state) return;

    mem_free(state->iv);
    mem_free(state);
}

void ORDO_CALLCONV
ofb_copy(struct OFB_STATE *dst,
         const struct OFB_STATE *src,
         const struct BLOCK_CIPHER *cipher)
{
    memcpy(dst->iv, src->iv, dst->block_size);
    dst->remaining = src->remaining;
}

size_t ORDO_CALLCONV
ofb_query(const struct BLOCK_CIPHER *cipher, int query, size_t value)
{
    switch(query)
    {
        case IV_LEN: return block_cipher_query(cipher, BLOCK_SIZE, 0);
        
        default: return 0;
    }
}
