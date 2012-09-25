#include <primitives/primitives.h>
#include <enc/enc_block.h>
#include <enc/block_cipher_modes/cbc.h>

/* This is extra context space required by the ECB mode to store temporary incomplete data buffers.*/
typedef struct CBC_ENCRYPT_CONTEXT
{
    /* A buffer for the IV. */
    void* iv;
    /* The temporary block, the size of the primitive's block size. */
    unsigned char* block;
    /* The amount of bytes of plaintext or ciphertext currently in the temporary block. */
    size_t available;
    /* Whether to pad the ciphertext. */
    size_t padding;
} CBC_ENCRYPT_CONTEXT;

/* Shorthand macro for context casting. */
#define cbc(ctx) ((CBC_ENCRYPT_CONTEXT*)ctx)

BLOCK_CIPHER_MODE_CONTEXT* CBC_Create(BLOCK_CIPHER_CONTEXT* cipherCtx)
{
    /* Allocate the context and extra buffers in it. */
    BLOCK_CIPHER_MODE_CONTEXT* ctx = salloc(sizeof(BLOCK_CIPHER_MODE_CONTEXT));
    if (ctx)
    {
        if ((ctx->ctx = salloc(sizeof(CBC_ENCRYPT_CONTEXT))))
        {
            /* Allocate extra buffers for the running IV and temporary block. */
            cbc(ctx->ctx)->iv = salloc(cipherCtx->cipher->blockSize);
            cbc(ctx->ctx)->block = salloc(cipherCtx->cipher->blockSize);

            /* Return if every allocation succeeded. */
            if ((cbc(ctx->ctx)->iv) && (cbc(ctx->ctx)->block))
            {
                cbc(ctx->ctx)->available = 0;
                return ctx;
            }

            /* Clean up if an error occurred. */
            sfree(cbc(ctx->ctx)->block, cipherCtx->cipher->blockSize);
            sfree(cbc(ctx->ctx)->iv, cipherCtx->cipher->blockSize);
            sfree(ctx->ctx, sizeof(CBC_ENCRYPT_CONTEXT));
        }
        sfree(ctx, sizeof(BLOCK_CIPHER_MODE_CONTEXT));
    }

    /* Allocation failed, return zero. */
    return 0;
}

int CBC_Init(BLOCK_CIPHER_MODE_CONTEXT* mode, BLOCK_CIPHER_CONTEXT* cipherCtx, void* iv, CBC_PARAMS* params)
{
    /* Copy the IV (required) into the context IV. */
    memcpy(cbc(mode->ctx)->iv, iv, cipherCtx->cipher->blockSize);

    /* Check and save the parameters. */
    cbc(mode->ctx)->padding = (params == 0) ? 1 : params->padding & 1;

    /* Return success. */
    return ORDO_ESUCCESS;
}

void CBC_EncryptUpdate(BLOCK_CIPHER_MODE_CONTEXT* mode, BLOCK_CIPHER_CONTEXT* cipherCtx, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
{
    /* Initialize output size. */
    *outlen = 0;

    /* Process all full blocks. */
    while (cbc(mode->ctx)->available + inlen >= cipherCtx->cipher->blockSize)
    {
        /* Copy it in, and process it. */
        memcpy(cbc(mode->ctx)->block + cbc(mode->ctx)->available, in, cipherCtx->cipher->blockSize - cbc(mode->ctx)->available);

        /* Exclusive-or the plaintext block with the running IV. */
        xorBuffer(cbc(mode->ctx)->block, cbc(mode->ctx)->iv, cipherCtx->cipher->blockSize);

        /* Encrypt the block. */
        cipherCtx->cipher->fForward(cipherCtx, cbc(mode->ctx)->block);

        /* Set this as the new running IV. */
        memcpy(cbc(mode->ctx)->iv, cbc(mode->ctx)->block, cipherCtx->cipher->blockSize);

        /* Write back the block to the output. */
        memcpy(out, cbc(mode->ctx)->block, cipherCtx->cipher->blockSize);
        *outlen += cipherCtx->cipher->blockSize;
        out += cipherCtx->cipher->blockSize;

        /* Go forward in the input buffer. */
        inlen -= cipherCtx->cipher->blockSize - cbc(mode->ctx)->available;
        in += cipherCtx->cipher->blockSize - cbc(mode->ctx)->available;
        cbc(mode->ctx)->available = 0;
    }

    /* Add whatever is left in the temporary buffer. */
    memcpy(cbc(mode->ctx)->block + cbc(mode->ctx)->available, in, inlen);
    cbc(mode->ctx)->available += inlen;
}

void CBC_DecryptUpdate(BLOCK_CIPHER_MODE_CONTEXT* mode, BLOCK_CIPHER_CONTEXT* cipherCtx, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
{
    /* Initialize output size. */
    *outlen = 0;

    /* Process all full blocks except the last potential block (if padding is disabled, also process the last block). */
    while (cbc(mode->ctx)->available + inlen > cipherCtx->cipher->blockSize - (1 - cbc(mode->ctx)->padding))
    {
        /* Copy it in, and process it. */
        memcpy(cbc(mode->ctx)->block + cbc(mode->ctx)->available, in, cipherCtx->cipher->blockSize - cbc(mode->ctx)->available);

        /* Save this ciphertext block. */
        memcpy(out, cbc(mode->ctx)->block, cipherCtx->cipher->blockSize);

        /* Decrypt the block. */
        cipherCtx->cipher->fInverse(cipherCtx, cbc(mode->ctx)->block);

        /* Exclusive-or the block with the running IV. */
        xorBuffer(cbc(mode->ctx)->block, cbc(mode->ctx)->iv, cipherCtx->cipher->blockSize);

        /* Get the original ciphertext back as running IV. */
        memcpy(cbc(mode->ctx)->iv, out, cipherCtx->cipher->blockSize);

        /* Write back the block to the output. */
        memcpy(out, cbc(mode->ctx)->block, cipherCtx->cipher->blockSize);
        *outlen += cipherCtx->cipher->blockSize;
        out += cipherCtx->cipher->blockSize;

        /* Go forward in the input buffer. */
        inlen -= cipherCtx->cipher->blockSize - cbc(mode->ctx)->available;
        in += cipherCtx->cipher->blockSize - cbc(mode->ctx)->available;
        cbc(mode->ctx)->available = 0;
    }

    /* Save the final block. */
    memcpy(cbc(mode->ctx)->block + cbc(mode->ctx)->available, in, inlen);
    cbc(mode->ctx)->available += inlen;
}

int CBC_EncryptFinal(BLOCK_CIPHER_MODE_CONTEXT* mode, BLOCK_CIPHER_CONTEXT* cipherCtx, unsigned char* out, size_t* outlen)
{
    unsigned char padding;

    /* If padding is disabled, we need to handle things differently. */
    if (cbc(mode->ctx)->padding == 0)
    {
        /* If there is data left, return an error and the number of plaintext left in outlen. */
        *outlen = cbc(mode->ctx)->available;
        if (*outlen != 0) return ORDO_ELEFTOVER;
    }
    else
    {
        /* Compute the amount of padding required. */
        padding = cipherCtx->cipher->blockSize - cbc(mode->ctx)->available % cipherCtx->cipher->blockSize;

        /* Write padding to the last block. */
        memset(cbc(mode->ctx)->block + cbc(mode->ctx)->available, padding, padding);

        /* Exclusive-or the last block with the running IV. */
        xorBuffer(cbc(mode->ctx)->block, cbc(mode->ctx)->iv, cipherCtx->cipher->blockSize);

        /* Encrypt the last block. */
        cipherCtx->cipher->fForward(cipherCtx, cbc(mode->ctx)->block);

        /* Write it out to the buffer. */
        memcpy(out, cbc(mode->ctx)->block, cipherCtx->cipher->blockSize);
        *outlen = cipherCtx->cipher->blockSize;
    }

    /* Return success. */
    return ORDO_ESUCCESS;
}

int CBC_DecryptFinal(BLOCK_CIPHER_MODE_CONTEXT* mode, BLOCK_CIPHER_CONTEXT* cipherCtx, unsigned char* out, size_t* outlen)
{
    unsigned char padding;

    /* If padding is disabled, we need to handle things differently. */
    if (!cbc(mode->ctx)->padding)
    {
        /* If there is data left, return an error and the number of plaintext left in outlen. */
        *outlen = cbc(mode->ctx)->available;
        if (*outlen != 0) return ORDO_ELEFTOVER;
    }
    else
    {
        /* Otherwise, decrypt the last block. */
        cipherCtx->cipher->fInverse(cipherCtx, cbc(mode->ctx)->block);

        /* Exclusive-or the last block with the running IV. */
        xorBuffer(cbc(mode->ctx)->block, cbc(mode->ctx)->iv, cipherCtx->cipher->blockSize);

        /* Read the amount of padding. */
        padding = *(cbc(mode->ctx)->block + cipherCtx->cipher->blockSize - 1);

        /* Check the padding. */
        if ((padding != 0) && (padding <= cipherCtx->cipher->blockSize) && (padCheck(cbc(mode->ctx)->block + cipherCtx->cipher->blockSize - padding, padding)))
        {
            /* Remove the padding data and output the plaintext. */
            *outlen = cipherCtx->cipher->blockSize - padding;
            memcpy(out, cbc(mode->ctx)->block, *outlen);
        }
        else
        {
            *outlen = 0;
            return ORDO_EPADDING;
        }
    }

    /* Return success. */
    return ORDO_ESUCCESS;
}

void CBC_Free(BLOCK_CIPHER_MODE_CONTEXT* mode, BLOCK_CIPHER_CONTEXT* cipherCtx)
{
    /* Deallocate context fields. */
    sfree(cbc(mode->ctx)->block, cipherCtx->cipher->blockSize);
    sfree(cbc(mode->ctx)->iv, cipherCtx->cipher->blockSize);
    sfree(mode->ctx, sizeof(CBC_ENCRYPT_CONTEXT));
    sfree(mode, sizeof(BLOCK_CIPHER_MODE_CONTEXT));
}

/* Fills a BLOCK_CIPHER_MODE struct with the correct information. */
void CBC_SetMode(BLOCK_CIPHER_MODE* mode)
{
    MAKE_BLOCK_CIPHER_MODE(mode, CBC_Create, CBC_Init, CBC_EncryptUpdate, CBC_DecryptUpdate, CBC_EncryptFinal, CBC_DecryptFinal, CBC_Free, "CBC");
}
