#include <primitives/primitives.h>
#include <encrypt/encrypt.h>
#include <encrypt/modes/ecb.h>

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

ENCRYPT_MODE_CONTEXT* ECB_Create(ENCRYPT_MODE* mode, CIPHER_PRIMITIVE_CONTEXT* cipher)
{
    /* Allocate the context and extra buffers in it. */
    ENCRYPT_MODE_CONTEXT* ctx = salloc(sizeof(ENCRYPT_MODE_CONTEXT));
    if (ctx)
    {
        ctx->mode = mode;
        ctx->ctx = salloc(sizeof(ECB_ENCRYPT_CONTEXT));
        if (ctx->ctx)
        {
            ecb(ctx->ctx)->block = salloc(cipher->primitive->szBlock);
            if (ecb(ctx->ctx)->block)
            {
                ecb(ctx->ctx)->available = 0;
                return ctx;
            }
            sfree(ctx->ctx, sizeof(ECB_ENCRYPT_CONTEXT));
        }
        sfree(ctx, sizeof(ENCRYPT_MODE_CONTEXT));
    }

    /* Allocation failed, return zero. */
    return 0;
}

int ECB_Init(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, void* iv, ECB_PARAMS* params)
{
    /* Check and save the parameters. */
    ecb(mode->ctx)->padding = (params == 0) ? 1 : params->padding;

    /* Return success. */
    return ORDO_ESUCCESS;
}

void ECB_EncryptUpdate(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
{
    /* Initialize output size. */
    *outlen = 0;

    /* Process all full blocks. */
    while (ecb(mode->ctx)->available + inlen >= cipher->primitive->szBlock)
    {
        /* Copy it in, and process it. */
        memcpy(ecb(mode->ctx)->block + ecb(mode->ctx)->available, in, cipher->primitive->szBlock - ecb(mode->ctx)->available);

        /* Encrypt the block. */
        cipher->primitive->fForward(cipher, ecb(mode->ctx)->block, cipher->primitive->szBlock);

        /* Write back the block to the output. */
        memcpy(out, ecb(mode->ctx)->block, cipher->primitive->szBlock);
        *outlen += cipher->primitive->szBlock;
        out += cipher->primitive->szBlock;

        /* Go forward in the input buffer. */
        inlen -= cipher->primitive->szBlock - ecb(mode->ctx)->available;
        in += cipher->primitive->szBlock - ecb(mode->ctx)->available;
        ecb(mode->ctx)->available = 0;
    }

    /* Add whatever is left in the temporary buffer. */
    memcpy(ecb(mode->ctx)->block + ecb(mode->ctx)->available, in, inlen);
    ecb(mode->ctx)->available += inlen;
}

void ECB_DecryptUpdate(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
{
    /* Initialize output size. */
    *outlen = 0;

    /* Process all full blocks except the last potential block (if padding is disabled, also process the last block). */
    while (ecb(mode->ctx)->available + inlen > cipher->primitive->szBlock - (1 - ecb(mode->ctx)->padding))
    {
        /* Copy it in, and process it. */
        memcpy(ecb(mode->ctx)->block + ecb(mode->ctx)->available, in, cipher->primitive->szBlock - ecb(mode->ctx)->available);

        /* Decrypt the block. */
        cipher->primitive->fInverse(cipher, ecb(mode->ctx)->block, cipher->primitive->szBlock);

        /* Write back the block to the output. */
        memcpy(out, ecb(mode->ctx)->block, cipher->primitive->szBlock);
        *outlen += cipher->primitive->szBlock;
        out += cipher->primitive->szBlock;

        /* Go forward in the input buffer. */
        inlen -= cipher->primitive->szBlock - ecb(mode->ctx)->available;
        in += cipher->primitive->szBlock - ecb(mode->ctx)->available;
        ecb(mode->ctx)->available = 0;
    }

    /* Save the final block. */
    memcpy(ecb(mode->ctx)->block + ecb(mode->ctx)->available, in, inlen);
    ecb(mode->ctx)->available += inlen;
}

int ECB_EncryptFinal(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* out, size_t* outlen)
{
    unsigned char padding;

    /* If padding is disabled, we need to handle things differently. */
    if (ecb(mode->ctx)->padding == 0)
    {
        /* If there is data left, return an error. */
        if (ecb(mode->ctx)->available != 0) return ORDO_ELEFTOVER;

        /* Otherwise, just set the output size to zero. */
        if (outlen != 0) *outlen = 0;
    }
    else
    {
        /* Compute the amount of padding required. */
        padding = cipher->primitive->szBlock - ecb(mode->ctx)->available % cipher->primitive->szBlock;

        /* Write padding to the last block. */
        memset(ecb(mode->ctx)->block + ecb(mode->ctx)->available, padding, padding);

        /* Encrypt the last block. */
        cipher->primitive->fForward(cipher, ecb(mode->ctx)->block, cipher->primitive->szBlock);

        /* Write it out to the buffer. */
        memcpy(out, ecb(mode->ctx)->block, cipher->primitive->szBlock);
        *outlen = cipher->primitive->szBlock;
    }

    /* Return success. */
    return ORDO_ESUCCESS;
}

int ECB_DecryptFinal(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* out, size_t* outlen)
{
    unsigned char padding;

    /* If padding is disabled, we need to handle things differently. */
    if (!ecb(mode->ctx)->padding)
    {
        /* If there is data left, return an error. */
        if (ecb(mode->ctx)->available != 0) return ORDO_ELEFTOVER;

        /* Otherwise, just set the output size to zero. */
        if (outlen != 0) *outlen = 0;
    }
    else
    {
        /* Otherwise, decrypt the last block. */
        cipher->primitive->fInverse(cipher, ecb(mode->ctx)->block, cipher->primitive->szBlock);

        /* Read the amount of padding. */
        padding = *(ecb(mode->ctx)->block + cipher->primitive->szBlock - 1);

        /* Check the padding. */
        if ((padding != 0) && (padding <= cipher->primitive->szBlock) && (padCheck(ecb(mode->ctx)->block + cipher->primitive->szBlock - padding, padding)))
        {
            /* Remove the padding data and output the plaintext. */
            *outlen = cipher->primitive->szBlock - padding;
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

void ECB_Free(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher)
{
    /* Dellocate context fields. */
    sfree(ecb(mode->ctx)->block, cipher->primitive->szBlock);
    sfree(mode->ctx, sizeof(ECB_ENCRYPT_CONTEXT));
    sfree(mode, sizeof(ENCRYPT_MODE_CONTEXT));
}

/* Fills a ENCRYPT_MODE struct with the correct information. */
void ECB_SetMode(ENCRYPT_MODE* mode)
{
    ENCRYPT_MAKEMODE(mode, ECB_Create, ECB_Init, ECB_EncryptUpdate, ECB_DecryptUpdate, ECB_EncryptFinal, ECB_DecryptFinal, ECB_Free, "ECB");
}
