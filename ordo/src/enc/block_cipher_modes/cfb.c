#include <primitives/primitives.h>
#include <enc/enc_block.h>
#include <enc/block_cipher_modes/cfb.h>

/* This is extra context space required by the CFB mode to store the amount of state not used.*/
typedef struct CFB_ENCRYPT_CONTEXT
{
    /* A buffer for the IV. */
    void* iv;
    /* The amount of bytes of unused state remaining before the state is to be renewed. */
    size_t remaining;
} CFB_ENCRYPT_CONTEXT;

/* Shorthand macro for context casting. */
#define cfb(ctx) ((CFB_ENCRYPT_CONTEXT*)ctx)

BLOCK_CIPHER_MODE_CONTEXT* CFB_Create(BLOCK_CIPHER_MODE* mode, BLOCK_CIPHER_CONTEXT* cipherCtx)
{
    /* Allocate the context and extra buffers in it. */
    BLOCK_CIPHER_MODE_CONTEXT* ctx = salloc(sizeof(BLOCK_CIPHER_MODE_CONTEXT));
    if (ctx)
    {
        ctx->mode = mode;
        if ((ctx->ctx = salloc(sizeof(CFB_ENCRYPT_CONTEXT))))
        {
            /* Return if everything succeeded. */
            if ((cfb(ctx->ctx)->iv = salloc(cipherCtx->cipher->blockSize)))
            {
                cfb(ctx->ctx)->remaining = 0;
                return ctx;
            }

            /* Clean up if an error occurred. */
            sfree(ctx->ctx, sizeof(CFB_ENCRYPT_CONTEXT));
        }
        sfree(ctx, sizeof(BLOCK_CIPHER_MODE_CONTEXT));
    }

    /* Allocation failed, return zero. */
    return 0;
}

int CFB_Init(BLOCK_CIPHER_MODE_CONTEXT* mode, BLOCK_CIPHER_CONTEXT* cipherCtx, void* iv, void* params)
{
    /* Copy the IV (required) into the context IV. */
    memcpy(cfb(mode->ctx)->iv, iv, cipherCtx->cipher->blockSize);

    /* Compute the initial keystream block. */
    cipherCtx->cipher->fForward(cipherCtx, cfb(mode->ctx)->iv);
    cfb(mode->ctx)->remaining = cipherCtx->cipher->blockSize;

    /* Return success. */
    return ORDO_ESUCCESS;
}

void CFB_EncryptUpdate(BLOCK_CIPHER_MODE_CONTEXT* mode, BLOCK_CIPHER_CONTEXT* cipherCtx, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
{
    /* Variable to store how much data can be processed per iteration. */
    size_t process = 0;

    /* Initialize the output size. */
    *outlen = 0;

    /* Go over the buffer byte per byte. */
    while (inlen != 0)
    {
        /* If there is no data left in the context block, update. */
        if (cfb(mode->ctx)->remaining == 0)
        {
            /* CFB update (simply apply the permutation function again). */
            cipherCtx->cipher->fForward(cipherCtx, cfb(mode->ctx)->iv);
            cfb(mode->ctx)->remaining = cipherCtx->cipher->blockSize;
        }

        /* Compute the amount of data to process. */
        process = (inlen < cfb(mode->ctx)->remaining) ? inlen : cfb(mode->ctx)->remaining;

        /* Process this amount of data. */
        if (out != in) memcpy(out, in, process);
        xorBuffer(out, (unsigned char*)cfb(mode->ctx)->iv + cipherCtx->cipher->blockSize - cfb(mode->ctx)->remaining, process);
        memcpy((unsigned char*)cfb(mode->ctx)->iv + cipherCtx->cipher->blockSize - cfb(mode->ctx)->remaining, out, process);
        cfb(mode->ctx)->remaining -= process;
        (*outlen) += process;
        inlen -= process;
        out += process;
        in += process;
    }
}

void CFB_DecryptUpdate(BLOCK_CIPHER_MODE_CONTEXT* mode, BLOCK_CIPHER_CONTEXT* cipherCtx, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
{
    /* Variable to store how much data can be processed per iteration. */
    size_t process = 0;

    /* Initialize the output size. */
    *outlen = 0;

    /* Go over the buffer byte per byte. */
    while (inlen != 0)
    {
        /* If there is no data left in the context block, update. */
        if (cfb(mode->ctx)->remaining == 0)
        {
            /* CFB update (simply apply the permutation function again). */
            cipherCtx->cipher->fForward(cipherCtx, cfb(mode->ctx)->iv);
            cfb(mode->ctx)->remaining = cipherCtx->cipher->blockSize;
        }

        /* Compute the amount of data to process. */
        process = (inlen < cfb(mode->ctx)->remaining) ? inlen : cfb(mode->ctx)->remaining;

        /* Process this amount of data. */
        if (out != in) memcpy(out, in, process);
        xorBuffer(out, (unsigned char*)cfb(mode->ctx)->iv + cipherCtx->cipher->blockSize - cfb(mode->ctx)->remaining, process);
        memcpy((unsigned char*)cfb(mode->ctx)->iv + cipherCtx->cipher->blockSize - cfb(mode->ctx)->remaining, in, process);
        cfb(mode->ctx)->remaining -= process;
        (*outlen) += process;
        inlen -= process;
        out += process;
        in += process;
    }
}

int CFB_Final(BLOCK_CIPHER_MODE_CONTEXT* mode, BLOCK_CIPHER_CONTEXT* cipherCtx, unsigned char* out, size_t* outlen)
{
    /* Write output size if applicable. */
    if (outlen) *outlen = 0;

    /* Return success. */
    return ORDO_ESUCCESS;
}

void CFB_Free(BLOCK_CIPHER_MODE_CONTEXT* mode, BLOCK_CIPHER_CONTEXT* cipherCtx)
{
    /* Free context space. */
    sfree(cfb(mode->ctx)->iv, cipherCtx->cipher->blockSize);
    sfree(mode->ctx, sizeof(CFB_ENCRYPT_CONTEXT));
    sfree(mode, sizeof(BLOCK_CIPHER_MODE_CONTEXT));
}

/* Fills a BLOCK_CIPHER_MODE struct with the correct information. */
void CFB_SetMode(BLOCK_CIPHER_MODE* mode)
{
    MAKE_BLOCK_CIPHER_MODE(mode, CFB_Create, CFB_Init, CFB_EncryptUpdate, CFB_DecryptUpdate, CFB_Final, CFB_Final, CFB_Free, "CFB");
}
