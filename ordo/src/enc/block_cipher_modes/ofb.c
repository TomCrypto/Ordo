#include <primitives/primitives.h>
#include <enc/enc_block.h>
#include <enc/block_cipher_modes/ofb.h>

/* This is extra context space required by the OFB mode to store the amount of state not used.*/
typedef struct OFB_ENCRYPT_CONTEXT
{
    /* A buffer for the IV. */
    void* iv;
    /* The amount of bytes of unused state remaining before the state is to be renewed. */
    size_t remaining;
} OFB_ENCRYPT_CONTEXT;

/* Shorthand macro for context casting. */
#define ofb(ctx) ((OFB_ENCRYPT_CONTEXT*)ctx)

BLOCK_CIPHER_MODE_CONTEXT* OFB_Create(BLOCK_CIPHER_MODE* mode, BLOCK_CIPHER_CONTEXT* cipherCtx)
{
    /* Allocate the context and extra buffers in it. */
    BLOCK_CIPHER_MODE_CONTEXT* ctx = salloc(sizeof(BLOCK_CIPHER_MODE_CONTEXT));
    if (ctx)
    {
        ctx->mode = mode;
        if ((ctx->ctx = salloc(sizeof(OFB_ENCRYPT_CONTEXT))))
        {
            /* Return if everything succeeded. */
            if ((ofb(ctx->ctx)->iv = salloc(cipherCtx->cipher->blockSize)))
            {
                ofb(ctx->ctx)->remaining = 0;
                return ctx;
            }

            /* Clean up if an error occurred. */
            sfree(ctx->ctx, sizeof(OFB_ENCRYPT_CONTEXT));
        }
        sfree(ctx, sizeof(BLOCK_CIPHER_MODE_CONTEXT));
    }

    /* Allocation failed, return zero. */
    return 0;
}

int OFB_Init(BLOCK_CIPHER_MODE_CONTEXT* mode, BLOCK_CIPHER_CONTEXT* cipherCtx, void* iv, void* params)
{
    /* Copy the IV (required) into the context IV. */
    memcpy(ofb(mode->ctx)->iv, iv, cipherCtx->cipher->blockSize);

    /* Compute the initial keystream block. */
    cipherCtx->cipher->fForward(cipherCtx, ofb(mode->ctx)->iv);
    ofb(mode->ctx)->remaining = cipherCtx->cipher->blockSize;

    /* Return success. */
    return ORDO_ESUCCESS;
}

void OFB_Update(BLOCK_CIPHER_MODE_CONTEXT* mode, BLOCK_CIPHER_CONTEXT* cipherCtx, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
{
    /* Variable to store how much data can be processed per iteration. */
    size_t process = 0;

    /* Initialize the output size. */
    *outlen = 0;

    /* Go over the buffer byte per byte. */
    while (inlen != 0)
    {
        /* If there is no data left in the context block, update. */
        if (ofb(mode->ctx)->remaining == 0)
        {
            /* OFB update (simply apply the permutation function again). */
            cipherCtx->cipher->fForward(cipherCtx, ofb(mode->ctx)->iv);
            ofb(mode->ctx)->remaining = cipherCtx->cipher->blockSize;
        }

        /* Compute the amount of data to process. */
        process = (inlen < ofb(mode->ctx)->remaining) ? inlen : ofb(mode->ctx)->remaining;

        /* Process this amount of data. */
        if (out != in) memcpy(out, in, process);
        xorBuffer(out, (unsigned char*)ofb(mode->ctx)->iv + cipherCtx->cipher->blockSize - ofb(mode->ctx)->remaining, process);
        ofb(mode->ctx)->remaining -= process;
        (*outlen) += process;
        inlen -= process;
        out += process;
        in += process;
    }
}

int OFB_Final(BLOCK_CIPHER_MODE_CONTEXT* mode, BLOCK_CIPHER_CONTEXT* cipherCtx, unsigned char* out, size_t* outlen)
{
    /* Write output size if applicable. */
    if (outlen) *outlen = 0;

    /* Return success. */
    return ORDO_ESUCCESS;
}

void OFB_Free(BLOCK_CIPHER_MODE_CONTEXT* mode, BLOCK_CIPHER_CONTEXT* cipherCtx)
{
    /* Free context space. */
    sfree(ofb(mode->ctx)->iv, cipherCtx->cipher->blockSize);
    sfree(mode->ctx, sizeof(OFB_ENCRYPT_CONTEXT));
    sfree(mode, sizeof(BLOCK_CIPHER_MODE_CONTEXT));
}

/* Fills a BLOCK_CIPHER_MODE struct with the correct information. */
void OFB_SetMode(BLOCK_CIPHER_MODE* mode)
{
    MAKE_BLOCK_CIPHER_MODE(mode, OFB_Create, OFB_Init, OFB_Update, OFB_Update, OFB_Final, OFB_Final, OFB_Free, "OFB");
}
