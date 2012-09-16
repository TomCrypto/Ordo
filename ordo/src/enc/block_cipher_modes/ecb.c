#include <primitives/primitives.h>
#include <enc/enc_block.h>
#include <enc/block_cipher_modes/ecb.h>

/* This is extra context space required by the ECB mode to store temporary incomplete data buffers.*/
typedef struct ECB_ENCRYPT_CONTEXT
{
    /* ,The temporary block, the size of the primitive's block size. */
    unsigned char* block;
    /* The amount of bytes of plaintext or ciphertext currently in the temporary block. */
    size_t available;
    /* Whether to pad the ciphertext. */
    size_t padding;
} ECB_ENCRYPT_CONTEXT;

/* Shorthand macro for context casting. */
#define ecb(ctx) ((ECB_ENCRYPT_CONTEXT*)ctx)

BLOCK_CIPHER_MODE_CONTEXT* ECB_Create(BLOCK_CIPHER_MODE* mode, BLOCK_CIPHER_CONTEXT* cipherCtx)
{
    /* Allocate the context and extra buffers in it. */
    BLOCK_CIPHER_MODE_CONTEXT* ctx = salloc(sizeof(BLOCK_CIPHER_MODE_CONTEXT));
    if (ctx)
    {
        ctx->mode = mode;
        if ((ctx->ctx = salloc(sizeof(ECB_ENCRYPT_CONTEXT))))
        {
            /* Return if everything succeeded. */
            if ((ecb(ctx->ctx)->block = salloc(cipherCtx->cipher->blockSize)))
            {
                ecb(ctx->ctx)->available = 0;
                return ctx;
            }

            /* Clean up if an error occurred. */
            sfree(ctx->ctx, sizeof(ECB_ENCRYPT_CONTEXT));
        }
        sfree(ctx, sizeof(BLOCK_CIPHER_MODE_CONTEXT));
    }

    /* Allocation failed, return zero. */
    return 0;
}

int ECB_Init(BLOCK_CIPHER_MODE_CONTEXT* mode, BLOCK_CIPHER_CONTEXT* cipherCtx, void* iv, ECB_PARAMS* params)
{
    /* Check and save the parameters. */
    ecb(mode->ctx)->padding = (params == 0) ? 1 : params->padding & 1;

    /* Return success. */
    return ORDO_ESUCCESS;
}

void ECB_EncryptUpdate(BLOCK_CIPHER_MODE_CONTEXT* mode, BLOCK_CIPHER_CONTEXT* cipherCtx, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
{
    /* Initialize output size. */
    *outlen = 0;

    /* Process all full blocks. */
    while (ecb(mode->ctx)->available + inlen >= cipherCtx->cipher->blockSize)
    {
        /* Copy it in, and process it. */
        memcpy(ecb(mode->ctx)->block + ecb(mode->ctx)->available, in, cipherCtx->cipher->blockSize - ecb(mode->ctx)->available);

        /* Encrypt the block. */
        cipherCtx->cipher->fForward(cipherCtx, ecb(mode->ctx)->block);

        /* Write back the block to the output. */
        memcpy(out, ecb(mode->ctx)->block, cipherCtx->cipher->blockSize);
        *outlen += cipherCtx->cipher->blockSize;
        out += cipherCtx->cipher->blockSize;

        /* Go forward in the input buffer. */
        inlen -= cipherCtx->cipher->blockSize - ecb(mode->ctx)->available;
        in += cipherCtx->cipher->blockSize - ecb(mode->ctx)->available;
        ecb(mode->ctx)->available = 0;
    }

    /* Add whatever is left in the temporary buffer. */
    memcpy(ecb(mode->ctx)->block + ecb(mode->ctx)->available, in, inlen);
    ecb(mode->ctx)->available += inlen;
}

void ECB_DecryptUpdate(BLOCK_CIPHER_MODE_CONTEXT* mode, BLOCK_CIPHER_CONTEXT* cipherCtx, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
{
    /* Initialize output size. */
    *outlen = 0;

    /* Process all full blocks except the last potential block (if padding is disabled, also process the last block). */
    while (ecb(mode->ctx)->available + inlen > cipherCtx->cipher->blockSize - (1 - ecb(mode->ctx)->padding))
    {
        /* Copy it in, and process it. */
        memcpy(ecb(mode->ctx)->block + ecb(mode->ctx)->available, in, cipherCtx->cipher->blockSize - ecb(mode->ctx)->available);

        /* Decrypt the block. */
        cipherCtx->cipher->fInverse(cipherCtx, ecb(mode->ctx)->block);

        /* Write back the block to the output. */
        memcpy(out, ecb(mode->ctx)->block, cipherCtx->cipher->blockSize);
        *outlen += cipherCtx->cipher->blockSize;
        out += cipherCtx->cipher->blockSize;

        /* Go forward in the input buffer. */
        inlen -= cipherCtx->cipher->blockSize - ecb(mode->ctx)->available;
        in += cipherCtx->cipher->blockSize - ecb(mode->ctx)->available;
        ecb(mode->ctx)->available = 0;
    }

    /* Save the final block. */
    memcpy(ecb(mode->ctx)->block + ecb(mode->ctx)->available, in, inlen);
    ecb(mode->ctx)->available += inlen;
}

int ECB_EncryptFinal(BLOCK_CIPHER_MODE_CONTEXT* mode, BLOCK_CIPHER_CONTEXT* cipherCtx, unsigned char* out, size_t* outlen)
{
    unsigned char padding;

    /* If padding is disabled, we need to handle things differently. */
    if (ecb(mode->ctx)->padding == 0)
    {
        /* If there is data left, return an error and the number of plaintext left in outlen. */
        *outlen = ecb(mode->ctx)->available;
        if (*outlen != 0) return ORDO_ELEFTOVER;
    }
    else
    {
        /* Compute the amount of padding required. */
        padding = cipherCtx->cipher->blockSize - ecb(mode->ctx)->available % cipherCtx->cipher->blockSize;

        /* Write padding to the last block. */
        memset(ecb(mode->ctx)->block + ecb(mode->ctx)->available, padding, padding);

        /* Encrypt the last block. */
        cipherCtx->cipher->fForward(cipherCtx, ecb(mode->ctx)->block);

        /* Write it out to the buffer. */
        memcpy(out, ecb(mode->ctx)->block, cipherCtx->cipher->blockSize);
        *outlen = cipherCtx->cipher->blockSize;
    }

    /* Return success. */
    return ORDO_ESUCCESS;
}

int ECB_DecryptFinal(BLOCK_CIPHER_MODE_CONTEXT* mode, BLOCK_CIPHER_CONTEXT* cipherCtx, unsigned char* out, size_t* outlen)
{
    unsigned char padding;

    /* If padding is disabled, we need to handle things differently. */
    if (!ecb(mode->ctx)->padding)
    {
        /* If there is data left, return an error and the number of plaintext left in outlen. */
        *outlen = ecb(mode->ctx)->available;
        if (*outlen != 0) return ORDO_ELEFTOVER;
    }
    else
    {
        /* Otherwise, decrypt the last block. */
        cipherCtx->cipher->fInverse(cipherCtx, ecb(mode->ctx)->block);

        /* Read the amount of padding. */
        padding = *(ecb(mode->ctx)->block + cipherCtx->cipher->blockSize - 1);

        /* Check the padding. */
        if ((padding != 0) && (padding <= cipherCtx->cipher->blockSize) && (padCheck(ecb(mode->ctx)->block + cipherCtx->cipher->blockSize - padding, padding)))
        {
            /* Remove the padding data and output the plaintext. */
            *outlen = cipherCtx->cipher->blockSize - padding;
            memcpy(out, ecb(mode->ctx)->block, *outlen);
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

void ECB_Free(BLOCK_CIPHER_MODE_CONTEXT* mode, BLOCK_CIPHER_CONTEXT* cipherCtx)
{
    /* Dellocate context fields. */
    sfree(ecb(mode->ctx)->block, cipherCtx->cipher->blockSize);
    sfree(mode->ctx, sizeof(ECB_ENCRYPT_CONTEXT));
    sfree(mode, sizeof(BLOCK_CIPHER_MODE_CONTEXT));
}

/* Fills a BLOCK_CIPHER_MODE struct with the correct information. */
void ECB_SetMode(BLOCK_CIPHER_MODE* mode)
{
    MAKE_ENCRYPT_MODE(mode, ECB_Create, ECB_Init, ECB_EncryptUpdate, ECB_DecryptUpdate, ECB_EncryptFinal, ECB_DecryptFinal, ECB_Free, "ECB");
}
