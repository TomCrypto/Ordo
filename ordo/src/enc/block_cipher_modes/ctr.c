#include <primitives/primitives.h>
#include <enc/enc_block.h>
#include <enc/block_cipher_modes/ctr.h>

/* This is extra context space required by the CTR mode to store the counter and the amount of state not used.*/
typedef struct CTR_ENCRYPT_CONTEXT
{
    /* A buffer for the IV. */
    void* iv;
    /* The counter value. */
    unsigned char* counter;
    /* The amount of bytes of unused state remaining before the state is to be renewed. */
    size_t remaining;
} CTR_ENCRYPT_CONTEXT;

/* Shorthand macro for context casting. */
#define ctr(ctx) ((CTR_ENCRYPT_CONTEXT*)ctx)

BLOCK_CIPHER_MODE_CONTEXT* CTR_Create(BLOCK_CIPHER_MODE* mode, BLOCK_CIPHER_CONTEXT* cipherCtx)
{
    /* Allocate the context and extra buffers in it. */
    BLOCK_CIPHER_MODE_CONTEXT* ctx = salloc(sizeof(BLOCK_CIPHER_MODE_CONTEXT));
    if (ctx)
    {
        ctx->mode = mode;
        if ((ctx->ctx = salloc(sizeof(CTR_ENCRYPT_CONTEXT))))
        {
            /* Allocate extra buffers for the IV and counter. */
            ctr(ctx->ctx)->iv = salloc(cipherCtx->cipher->blockSize);
            ctr(ctx->ctx)->counter = salloc(cipherCtx->cipher->blockSize);

            /* Return if everything succeeded. */
            if ((ctr(ctx->ctx)->iv) && (ctr(ctx->ctx)->counter))
            {
                ctr(ctx->ctx)->remaining = 0;
                return ctx;
            }

            /* Clean up if an error occurred. */
            sfree(ctr(ctx->ctx)->counter, cipherCtx->cipher->blockSize);
            sfree(ctr(ctx->ctx)->iv, cipherCtx->cipher->blockSize);
            sfree(ctx->ctx, sizeof(CTR_ENCRYPT_CONTEXT));
        }
        sfree(ctx, sizeof(BLOCK_CIPHER_MODE_CONTEXT));
    }

    /* Allocation failed, return zero. */
    return 0;
}

int CTR_Init(BLOCK_CIPHER_MODE_CONTEXT* mode, BLOCK_CIPHER_CONTEXT* cipherCtx, void* iv, void* params)
{
    /* Copy the IV (required) into the context IV. */
    memcpy(ctr(mode->ctx)->iv, iv, cipherCtx->cipher->blockSize);

    /* Copy the IV into the counter. */
    memcpy(ctr(mode->ctx)->counter, ctr(mode->ctx)->iv, cipherCtx->cipher->blockSize);

    /* Compute the initial keystream block. */
    cipherCtx->cipher->fForward(cipherCtx, ctr(mode->ctx)->iv);
    ctr(mode->ctx)->remaining = cipherCtx->cipher->blockSize;

    /* Return success. */
    return ORDO_ESUCCESS;
}

void CTR_Update(BLOCK_CIPHER_MODE_CONTEXT* mode, BLOCK_CIPHER_CONTEXT* cipherCtx, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
{
    /* Variable to store how much data can be processed per iteration. */
    size_t process = 0;

    /* Initialize the output size. */
    *outlen = 0;

    /* Go over the input buffer byte per byte. */
    while (inlen != 0)
    {
        /* If there is no data left in the context block, update. */
        if (ctr(mode->ctx)->remaining == 0)
        {
            /* CTR update (increment counter, copy counter into IV, encrypt IV). */
            incBuffer(ctr(mode->ctx)->counter, cipherCtx->cipher->blockSize);
            memcpy(ctr(mode->ctx)->iv, ctr(mode->ctx)->counter, cipherCtx->cipher->blockSize);
            cipherCtx->cipher->fForward(cipherCtx, ctr(mode->ctx)->iv);
            ctr(mode->ctx)->remaining = cipherCtx->cipher->blockSize;
        }

        /* Compute the amount of data to process. */
        process = (inlen < ctr(mode->ctx)->remaining) ? inlen : ctr(mode->ctx)->remaining;

        /* Process this amount of data. */
        if (out != in) memcpy(out, in, process);
        xorBuffer(out, (unsigned char*)ctr(mode->ctx)->iv + cipherCtx->cipher->blockSize - ctr(mode->ctx)->remaining, process);
        ctr(mode->ctx)->remaining -= process;
        (*outlen) += process;
        inlen -= process;
        out += process;
        in += process;
    }
}

int CTR_Final(BLOCK_CIPHER_MODE_CONTEXT* mode, BLOCK_CIPHER_CONTEXT* cipherCtx, unsigned char* out, size_t* outlen)
{
    /* Write output size if applicable. */
    if (outlen) *outlen = 0;

    /* Return success. */
    return ORDO_ESUCCESS;
}

void CTR_Free(BLOCK_CIPHER_MODE_CONTEXT* mode, BLOCK_CIPHER_CONTEXT* cipherCtx)
{
    /* Free context space. */
    sfree(ctr(mode->ctx)->counter, cipherCtx->cipher->blockSize);
    sfree(ctr(mode->ctx)->iv, cipherCtx->cipher->blockSize);
    sfree(mode->ctx, sizeof(CTR_ENCRYPT_CONTEXT));
    sfree(mode, sizeof(BLOCK_CIPHER_MODE_CONTEXT));
}

/* Fills a BLOCK_CIPHER_MODE struct with the correct information. */
void CTR_SetMode(BLOCK_CIPHER_MODE* mode)
{
    MAKE_BLOCK_CIPHER_MODE(mode, CTR_Create, CTR_Init, CTR_Update, CTR_Update, CTR_Final, CTR_Final, CTR_Free, "CTR");
}
