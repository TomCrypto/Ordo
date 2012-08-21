/**
 * @file ecb.c
 * Implements the ECB mode of operation. The ECB mode is a block mode of operation, meaning that it performs
 * padding. It works by taking each block and feeding it into the permutation function, taking the output
 * as the ciphertext. To decrypt, the ciphertext it passed through the inverse permutation function to recover
 * the plaintext. The padding algorithm is PKCS7 (RFC 5652), which appends N bytes of value N, where N is the
 * number of padding bytes required (between 1 and the cipher's block size in bytes).
 *
 * Note that the ECB mode is generally insecure and is not recommended for use.
 *
 * @see ecb.h
 */

#include <primitives/primitives.h>
#include <encrypt/encrypt.h>
#include <encrypt/modes/ecb.h>

void ECB_Create(ECB_ENCRYPT_CONTEXT* ctx)
{
    /* Allocate context fields. */
    ctx->key = salloc(ctx->primitive->szKey);
    ctx->reserved = salloc(sizeof(ECB_RESERVED));
    ctx->reserved->block = salloc(ctx->primitive->szBlock);
    ctx->reserved->available = 0;
}

/*! Initializes an ECB context (the primitive and mode must have been filled in).
  \param context The initialized encryption context.
  \param key A pointer to the key to use for encryption.
  \param keySize The size, in bytes, of the key.
  \param tweak The tweak to use (this may be zero, depending on the primitive).
  \param iv Set this to zero, as the ECB mode uses no initialization vector.
  \return Returns 0 on success, and a negative value on failure. Possible errors are:
  ORDO_EKEYSIZE: the key size is not valid for the context's primitive. */
int ECB_Init(ECB_ENCRYPT_CONTEXT* ctx, void* key, size_t keySize, void* tweak, void* iv, void* params)
{
    /* Check the key size. */
    if (!ctx->primitive->fKeyCheck(keySize)) return ORDO_EKEYSIZE;

    /* Perform the key schedule. */
    ctx->primitive->fKeySchedule(key, keySize, tweak, ctx->key, params);

    /* Return success. */
    return ORDO_ESUCCESS;
}

/*! Encrypts a buffer in ECB mode. The context must have been allocated and initialized.
  \param context The initialized encryption context.
  \param in A pointer to the plaintext buffer.
  \param inlen The size of the plaintext buffer, in bytes.
  \param out A pointer to the ciphertext buffer.
  \param outlen A pointer to an integer which will contain the amount of ciphertext output, in bytes.
  \return Returns true on success, false on failure.
  \remark The out buffer must have enough space to accomodate up to one more block size of ciphertext than plaintext, rounded down to the nearest block. */
void ECB_EncryptUpdate(ECB_ENCRYPT_CONTEXT* ctx, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
{
    /* Initialize output size. */
    *outlen = 0;

    /* Process all full blocks. */
    while (ctx->reserved->available + inlen >= ctx->primitive->szBlock)
    {
        /* Copy it in, and process it. */
        memcpy(ctx->reserved->block + ctx->reserved->available, in, ctx->primitive->szBlock - ctx->reserved->available);

        /* Encrypt the block. */
        ctx->primitive->fForward(ctx->reserved->block, ctx->key);

        /* Write back the block to the output. */
        memcpy(out, ctx->reserved->block, ctx->primitive->szBlock);
        *outlen += ctx->primitive->szBlock;
        out += ctx->primitive->szBlock;

        /* Go forward in the input buffer. */
        inlen -= ctx->primitive->szBlock - ctx->reserved->available;
        in += ctx->primitive->szBlock - ctx->reserved->available;
        ctx->reserved->available = 0;
    }

    /* Add whatever is left in the temporary buffer. */
    memcpy(ctx->reserved->block + ctx->reserved->available, in, inlen);
    ctx->reserved->available += inlen;
}

/*! Decrypts a buffer in ECB mode. The context must have been allocated and initialized.
  \param context The initialized encryption context.
  \param in A pointer to the ciphertext buffer.
  \param inlen The size of the ciphertext buffer, in bytes.
  \param out A pointer to the plaintext buffer.
  \param outlen A pointer to an integer which will contain the amount of plaintext output, in bytes.
  \remark The out buffer must have enough space to accomodate up to one more block size of plaintext than ciphertext, rounded down to the nearest block. */
void ECB_DecryptUpdate(ECB_ENCRYPT_CONTEXT* ctx, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
{
    /* Initialize output size. */
    *outlen = 0;

    /* Process all full blocks except the last potential block (if padding is disabled, also process the last block). */
    while (ctx->reserved->available + inlen > ctx->primitive->szBlock - (1 - ctx->padding))
    {
        /* Copy it in, and process it. */
        memcpy(ctx->reserved->block + ctx->reserved->available, in, ctx->primitive->szBlock - ctx->reserved->available);

        /* Decrypt the block. */
        ctx->primitive->fInverse(ctx->reserved->block, ctx->key);

        /* Write back the block to the output. */
        memcpy(out, ctx->reserved->block, ctx->primitive->szBlock);
        *outlen += ctx->primitive->szBlock;
        out += ctx->primitive->szBlock;

        /* Go forward in the input buffer. */
        inlen -= ctx->primitive->szBlock - ctx->reserved->available;
        in += ctx->primitive->szBlock - ctx->reserved->available;
        ctx->reserved->available = 0;
    }

    /* Save the final block. */
    memcpy(ctx->reserved->block + ctx->reserved->available, in, inlen);
    ctx->reserved->available += inlen;
}

/*! Finalizes an encryption context in ECB mode. The context must have been allocated and initialized.
  \param context The initialized encryption context.
  \param out A pointer to the final plaintext/ciphertext buffer.
  \param outlen A pointer to an integer which will contain the amount of plaintext output, in bytes.
  \return Returns true on success, false on failure.
  \remark The out buffer must have enough space to accomodate up to one block size of plaintext for padding. */
int ECB_EncryptFinal(ECB_ENCRYPT_CONTEXT* ctx, unsigned char* out, size_t* outlen)
{
    unsigned char padding;

    /* If padding is disabled, we need to handle things differently. */
    if (ctx->padding == 0)
    {
        /* If there is data left, return an error. */
        if (ctx->reserved->available != 0) return ORDO_LEFTOVER;

        /* Otherwise, just set the output size to zero. */
        if (outlen != 0) *outlen = 0;
    }
    else
    {
        /* Compute the amount of padding required. */
        padding = ctx->primitive->szBlock - ctx->reserved->available % ctx->primitive->szBlock;

        /* Write padding to the last block. */
        memset(ctx->reserved->block + ctx->reserved->available, padding, padding);

        /* Encrypt the last block. */
        ctx->primitive->fForward(ctx->reserved->block, ctx->key);

        /* Write it out to the buffer. */
        memcpy(out, ctx->reserved->block, ctx->primitive->szBlock);
        *outlen = ctx->primitive->szBlock;
    }

    /* Return success. */
    return ORDO_ESUCCESS;
}

int ECB_DecryptFinal(ECB_ENCRYPT_CONTEXT* ctx, unsigned char* out, size_t* outlen)
{
    unsigned char padding;

    /* If padding is disabled, we need to handle things differently. */
    if (!ctx->padding)
    {
        /* If there is data left, return an error. */
        if (ctx->reserved->available != 0) return ORDO_LEFTOVER;

        /* Otherwise, just set the output size to zero. */
        if (outlen != 0) *outlen = 0;
    }
    else
    {
        /* Otherwise, decrypt the last block. */
        ctx->primitive->fInverse(ctx->reserved->block, ctx->key);

        /* Read the amount of padding. */
        padding = *(ctx->reserved->block + ctx->primitive->szBlock - 1);

        /* Check the padding. */
        if ((padding != 0) && (padding <= ctx->primitive->szBlock) && (padCheck(ctx->reserved->block + ctx->primitive->szBlock - padding, padding)))
        {
            /* Remove the padding data and output the plaintext. */
            *outlen = ctx->primitive->szBlock - padding;
            memcpy(out, ctx->reserved->block, *outlen);
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

void ECB_Free(ECB_ENCRYPT_CONTEXT* ctx)
{
    /* Dellocate context fields. */
    sfree(ctx->reserved->block, ctx->primitive->szBlock);
    sfree(ctx->reserved, sizeof(ECB_RESERVED));
    sfree(ctx->key, ctx->primitive->szKey);
}

/* Fills a ENCRYPT_MODE struct with the correct information. */
void ECB_SetMode(ENCRYPT_MODE* mode)
{
    ENCRYPT_MAKEMODE(mode, ECB_Create, ECB_Init, ECB_EncryptUpdate, ECB_DecryptUpdate, ECB_EncryptFinal, ECB_DecryptFinal, ECB_Free, "ECB");
}
