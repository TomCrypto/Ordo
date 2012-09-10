#include <primitives/primitives.h>
#include <encrypt/encrypt.h>
#include <encrypt/modes/cbc.h>

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

ENCRYPT_MODE_CONTEXT* CBC_Create(ENCRYPT_MODE* mode, CIPHER_PRIMITIVE_CONTEXT* cipher)
{
    /* Allocate the context and extra buffers in it. */
    ENCRYPT_MODE_CONTEXT* ctx = salloc(sizeof(ENCRYPT_MODE_CONTEXT));
    if (ctx)
    {
        ctx->mode = mode;
        ctx->ctx = salloc(sizeof(CBC_ENCRYPT_CONTEXT));
        if (ctx->ctx)
        {
            cbc(ctx->ctx)->iv = salloc(cipher->primitive->szBlock);
            if (cbc(ctx->ctx)->iv)
            {
                cbc(ctx->ctx)->block = salloc(cipher->primitive->szBlock);
                if (cbc(ctx->ctx)->block)
                {
                    cbc(ctx->ctx)->available = 0;
                    return ctx;
                }
                sfree(cbc(ctx->ctx)->iv, cipher->primitive->szBlock);
            }
            sfree(ctx->ctx, sizeof(CBC_ENCRYPT_CONTEXT));
        }
        sfree(ctx, sizeof(ENCRYPT_MODE_CONTEXT));
    }

    /* Allocation failed, return zero. */
    return 0;
}

int CBC_Init(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, void* iv, CBC_PARAMS* params)
{
    /* Copy the IV (required) into the context IV. */
    memcpy(cbc(mode->ctx)->iv, iv, cipher->primitive->szBlock);

    /* Check and save the parameters. */
    cbc(mode->ctx)->padding = (params == 0) ? 1 : params->padding;

    /* Return success. */
    return ORDO_ESUCCESS;
}

void CBC_EncryptUpdate(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
{
    /* Initialize output size. */
    *outlen = 0;

    /* Process all full blocks. */
    while (cbc(mode->ctx)->available + inlen >= cipher->primitive->szBlock)
    {
        /* Copy it in, and process it. */
        memcpy(cbc(mode->ctx)->block + cbc(mode->ctx)->available, in, cipher->primitive->szBlock - cbc(mode->ctx)->available);

        /* Exclusive-or the plaintext block with the running IV. */
        xorBuffer(cbc(mode->ctx)->block, cbc(mode->ctx)->iv, cipher->primitive->szBlock);

        /* Encrypt the block. */
        cipher->primitive->fForward(cipher, cbc(mode->ctx)->block, cipher->primitive->szBlock);

        /* Set this as the new running IV. */
        memcpy(cbc(mode->ctx)->iv, cbc(mode->ctx)->block, cipher->primitive->szBlock);

        /* Write back the block to the output. */
        memcpy(out, cbc(mode->ctx)->block, cipher->primitive->szBlock);
        *outlen += cipher->primitive->szBlock;
        out += cipher->primitive->szBlock;

        /* Go forward in the input buffer. */
        inlen -= cipher->primitive->szBlock - cbc(mode->ctx)->available;
        in += cipher->primitive->szBlock - cbc(mode->ctx)->available;
        cbc(mode->ctx)->available = 0;
    }

    /* Add whatever is left in the temporary buffer. */
    memcpy(cbc(mode->ctx)->block + cbc(mode->ctx)->available, in, inlen);
    cbc(mode->ctx)->available += inlen;
}

void CBC_DecryptUpdate(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
{
    /* Initialize output size. */
    *outlen = 0;

    /* Process all full blocks except the last potential block (if padding is disabled, also process the last block). */
    while (cbc(mode->ctx)->available + inlen > cipher->primitive->szBlock - (1 - cbc(mode->ctx)->padding))
    {
        /* Copy it in, and process it. */
        memcpy(cbc(mode->ctx)->block + cbc(mode->ctx)->available, in, cipher->primitive->szBlock - cbc(mode->ctx)->available);

        /* Save this ciphertext block. */
        memcpy(out, cbc(mode->ctx)->block, cipher->primitive->szBlock);

        /* Decrypt the block. */
        cipher->primitive->fInverse(cipher, cbc(mode->ctx)->block, cipher->primitive->szBlock);

        /* Exclusive-or the block with the running IV. */
        xorBuffer(cbc(mode->ctx)->block, cbc(mode->ctx)->iv, cipher->primitive->szBlock);

        /* Get the original ciphertext back as running IV. */
        memcpy(cbc(mode->ctx)->iv, out, cipher->primitive->szBlock);

        /* Write back the block to the output. */
        memcpy(out, cbc(mode->ctx)->block, cipher->primitive->szBlock);
        *outlen += cipher->primitive->szBlock;
        out += cipher->primitive->szBlock;

        /* Go forward in the input buffer. */
        inlen -= cipher->primitive->szBlock - cbc(mode->ctx)->available;
        in += cipher->primitive->szBlock - cbc(mode->ctx)->available;
        cbc(mode->ctx)->available = 0;
    }

    /* Save the final block. */
    memcpy(cbc(mode->ctx)->block + cbc(mode->ctx)->available, in, inlen);
    cbc(mode->ctx)->available += inlen;
}

int CBC_EncryptFinal(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* out, size_t* outlen)
{
    unsigned char padding;

    /* If padding is disabled, we need to handle things differently. */
    if (cbc(mode->ctx)->padding == 0)
    {
        /* If there is data left, return an error. */
        if (cbc(mode->ctx)->available != 0) return ORDO_ELEFTOVER;

        /* Otherwise, just set the output size to zero. */
        if (outlen != 0) *outlen = 0;
    }
    else
    {
        /* Compute the amount of padding required. */
        padding = cipher->primitive->szBlock - cbc(mode->ctx)->available % cipher->primitive->szBlock;

        /* Write padding to the last block. */
        memset(cbc(mode->ctx)->block + cbc(mode->ctx)->available, padding, padding);

        /* Exclusive-or the last block with the running IV. */
        xorBuffer(cbc(mode->ctx)->block, cbc(mode->ctx)->iv, cipher->primitive->szBlock);

        /* Encrypt the last block. */
        cipher->primitive->fForward(cipher, cbc(mode->ctx)->block, cipher->primitive->szBlock);

        /* Write it out to the buffer. */
        memcpy(out, cbc(mode->ctx)->block, cipher->primitive->szBlock);
        *outlen = cipher->primitive->szBlock;
    }

    /* Return success. */
    return ORDO_ESUCCESS;
}

int CBC_DecryptFinal(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* out, size_t* outlen)
{
    unsigned char padding;

    /* If padding is disabled, we need to handle things differently. */
    if (!cbc(mode->ctx)->padding)
    {
        /* If there is data left, return an error. */
        if (cbc(mode->ctx)->available != 0) return ORDO_ELEFTOVER;

        /* Otherwise, just set the output size to zero. */
        if (outlen != 0) *outlen = 0;
    }
    else
    {
        /* Otherwise, decrypt the last block. */
        cipher->primitive->fInverse(cipher, cbc(mode->ctx)->block, cipher->primitive->szBlock);

        /* Exclusive-or the last block with the running IV. */
        xorBuffer(cbc(mode->ctx)->block, cbc(mode->ctx)->iv, cipher->primitive->szBlock);

        /* Read the amount of padding. */
        padding = *(cbc(mode->ctx)->block + cipher->primitive->szBlock - 1);

        /* Check the padding. */
        if ((padding != 0) && (padding <= cipher->primitive->szBlock) && (padCheck(cbc(mode->ctx)->block + cipher->primitive->szBlock - padding, padding)))
        {
            /* Remove the padding data and output the plaintext. */
            *outlen = cipher->primitive->szBlock - padding;
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

void CBC_Free(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher)
{
    /* Deallocate context fields. */
    sfree(cbc(mode->ctx)->block, cipher->primitive->szBlock);
    sfree(cbc(mode->ctx)->iv, cipher->primitive->szBlock);
    sfree(mode->ctx, sizeof(CBC_ENCRYPT_CONTEXT));
    sfree(mode, sizeof(ENCRYPT_MODE_CONTEXT));
}

/* Fills a ENCRYPT_MODE struct with the correct information. */
void CBC_SetMode(ENCRYPT_MODE* mode)
{
    ENCRYPT_MAKEMODE(mode, CBC_Create, CBC_Init, CBC_EncryptUpdate, CBC_DecryptUpdate, CBC_EncryptFinal, CBC_DecryptFinal, CBC_Free, "CBC");
}
