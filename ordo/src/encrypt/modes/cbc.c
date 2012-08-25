/**
 * @file cbc.c
 * Implements the CBC mode of operation. The CBC mode is a block mode of operation, meaning that it performs
 * padding. It works by taking each block and XORing it with the IV. That ciphertext block then becomes the
 * IV for the next block to encrypt. Decryption is done by inverting this process. The padding algorithm is
 * PKCS7 (RFC 5652), which appends N bytes of value N, where N is the number of padding bytes required
 * (between 1 and the cipher's block size in bytes).
 *
 * @see cbc.h
 */

#include <primitives/primitives.h>
#include <encrypt/encrypt.h>
#include <encrypt/modes/cbc.h>

/*! This is extra context space required by the ECB mode to store temporary incomplete data buffers.*/
typedef struct CBC_ENCRYPT_CONTEXT
{
    /*! A buffer for the key. */
    void* key;
    /*! A buffer for the IV. */
    void* iv;
    /*! The temporary block, the size of the primitive's block size. */
    unsigned char* block;
    /*! The amount of bytes of plaintext or ciphertext currently in the temporary block. */
    size_t available;
} CBC_ENCRYPT_CONTEXT;

/*! Shorthand macro for context casting. */
#define cbc(ctx) ((CBC_ENCRYPT_CONTEXT*)ctx)

void CBC_Create(ENCRYPT_CONTEXT* ctx)
{
    /* Allocate context fields. */
    ctx->ctx = salloc(sizeof(CBC_ENCRYPT_CONTEXT));
    cbc(ctx->ctx)->key = salloc(ctx->primitive->szKey);
    cbc(ctx->ctx)->iv = salloc(ctx->primitive->szBlock);
    cbc(ctx->ctx)->block = salloc(ctx->primitive->szBlock);
    cbc(ctx->ctx)->available = 0;
}

/*! Initializes an CBC context (the primitive and mode must have been filled in).
  \param context The initialized encryption context.
  \param key A pointer to the key to use for encryption.
  \param keySize The size, in bytes, of the key.
  \param tweak The tweak to use (this may be zero, depending on the primitive).
  \param iv A pointer to the IV to use for encryption.
  \return Returns 0 on success, and a negative value on failure. Possible errors are:
  ORDO_EKEYSIZE: the key size is not valid for the context's primitive. */
int CBC_Init(ENCRYPT_CONTEXT* ctx, void* key, size_t keySize, void* tweak, void* iv, void* params)
{
    /* Check the key size. */
    if (!ctx->primitive->fKeyCheck(keySize)) return ORDO_EKEYSIZE;

    /* Copy the IV (required) into the context IV. */
    memcpy(cbc(ctx->ctx)->iv, iv, ctx->primitive->szBlock);

    /* Perform the key schedule. */
    ctx->primitive->fKeySchedule(key, keySize, tweak, cbc(ctx->ctx)->key, params);

    /* Return success. */
    return ORDO_ESUCCESS;
}

/*! Encrypts a buffer in CBC mode. The context must have been allocated and initialized.
  \param context The initialized encryption context.
  \param in A pointer to the plaintext buffer.
  \param inlen The size of the plaintext buffer, in bytes.
  \param out A pointer to the ciphertext buffer.
  \param outlen A pointer to an integer which will contain the amount of ciphertext output, in bytes.
  \return Returns true on success, false on failure.
  \remark The out buffer must have enough space to accomodate up to one more block size of ciphertext than plaintext, rounded down to the nearest block. */
void CBC_EncryptUpdate(ENCRYPT_CONTEXT* ctx, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
{
    /* Initialize output size. */
    *outlen = 0;

    /* Process all full blocks. */
    while (cbc(ctx->ctx)->available + inlen >= ctx->primitive->szBlock)
    {
        /* Copy it in, and process it. */
        memcpy(cbc(ctx->ctx)->block + cbc(ctx->ctx)->available, in, ctx->primitive->szBlock - cbc(ctx->ctx)->available);

        /* Exclusive-or the plaintext block with the running IV. */
        xorBuffer(cbc(ctx->ctx)->block, cbc(ctx->ctx)->iv, ctx->primitive->szBlock);

        /* Encrypt the block. */
        ctx->primitive->fForward(cbc(ctx->ctx)->block, cbc(ctx->ctx)->key);

        /* Set this as the new running IV. */
        memcpy(cbc(ctx->ctx)->iv, cbc(ctx->ctx)->block, ctx->primitive->szBlock);

        /* Write back the block to the output. */
        memcpy(out, cbc(ctx->ctx)->block, ctx->primitive->szBlock);
        *outlen += ctx->primitive->szBlock;
        out += ctx->primitive->szBlock;

        /* Go forward in the input buffer. */
        inlen -= ctx->primitive->szBlock - cbc(ctx->ctx)->available;
        in += ctx->primitive->szBlock - cbc(ctx->ctx)->available;
        cbc(ctx->ctx)->available = 0;
    }

    /* Add whatever is left in the temporary buffer. */
    memcpy(cbc(ctx->ctx)->block + cbc(ctx->ctx)->available, in, inlen);
    cbc(ctx->ctx)->available += inlen;
}

/*! Decrypts a buffer in CBC mode. The context must have been allocated and initialized.
  \param context The initialized encryption context.
  \param in A pointer to the ciphertext buffer.
  \param inlen The size of the ciphertext buffer, in bytes.
  \param out A pointer to the plaintext buffer.
  \param outlen A pointer to an integer which will contain the amount of plaintext output, in bytes.
  \remark The out buffer must have enough space to accomodate up to one more block size of plaintext than ciphertext, rounded down to the nearest block. */
void CBC_DecryptUpdate(ENCRYPT_CONTEXT* ctx, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
{
    /* Initialize output size. */
    *outlen = 0;

    /* Process all full blocks except the last potential block (if padding is disabled, also process the last block). */
    while (cbc(ctx->ctx)->available + inlen > ctx->primitive->szBlock - (1 - ctx->padding))
    {
        /* Copy it in, and process it. */
        memcpy(cbc(ctx->ctx)->block + cbc(ctx->ctx)->available, in, ctx->primitive->szBlock - cbc(ctx->ctx)->available);

        /* Save this ciphertext block. */
        memcpy(out, cbc(ctx->ctx)->block, ctx->primitive->szBlock);

        /* Decrypt the block. */
        ctx->primitive->fInverse(cbc(ctx->ctx)->block, cbc(ctx->ctx)->key);

        /* Exclusive-or the block with the running IV. */
        xorBuffer(cbc(ctx->ctx)->block, cbc(ctx->ctx)->iv, ctx->primitive->szBlock);

        /* Get the original ciphertext back as running IV. */
        memcpy(cbc(ctx->ctx)->iv, out, ctx->primitive->szBlock);

        /* Write back the block to the output. */
        memcpy(out, cbc(ctx->ctx)->block, ctx->primitive->szBlock);
        *outlen += ctx->primitive->szBlock;
        out += ctx->primitive->szBlock;

        /* Go forward in the input buffer. */
        inlen -= ctx->primitive->szBlock - cbc(ctx->ctx)->available;
        in += ctx->primitive->szBlock - cbc(ctx->ctx)->available;
        cbc(ctx->ctx)->available = 0;
    }

    /* Save the final block. */
    memcpy(cbc(ctx->ctx)->block + cbc(ctx->ctx)->available, in, inlen);
    cbc(ctx->ctx)->available += inlen;
}

/*! Finalizes an encryption context in CBC mode. The context must have been allocated and initialized.
  \param context The initialized encryption context.
  \param out A pointer to the final plaintext/ciphertext buffer.
  \param outlen A pointer to an integer which will contain the amount of plaintext output, in bytes.
  \return Returns true on success, false on failure.
  \remark The out buffer must have enough space to accomodate up to one block size of plaintext for padding. */
int CBC_EncryptFinal(ENCRYPT_CONTEXT* ctx, unsigned char* out, size_t* outlen)
{
    unsigned char padding;

    /* If padding is disabled, we need to handle things differently. */
    if (ctx->padding == 0)
    {
        /* If there is data left, return an error. */
        if (cbc(ctx->ctx)->available != 0) return ORDO_LEFTOVER;

        /* Otherwise, just set the output size to zero. */
        if (outlen != 0) *outlen = 0;
    }
    else
    {
        /* Compute the amount of padding required. */
        padding = ctx->primitive->szBlock - cbc(ctx->ctx)->available % ctx->primitive->szBlock;

        /* Write padding to the last block. */
        memset(cbc(ctx->ctx)->block + cbc(ctx->ctx)->available, padding, padding);

        /* Exclusive-or the last block with the running IV. */
        xorBuffer(cbc(ctx->ctx)->block, cbc(ctx->ctx)->iv, ctx->primitive->szBlock);

        /* Encrypt the last block. */
        ctx->primitive->fForward(cbc(ctx->ctx)->block, cbc(ctx->ctx)->key);

        /* Write it out to the buffer. */
        memcpy(out, cbc(ctx->ctx)->block, ctx->primitive->szBlock);
        *outlen = ctx->primitive->szBlock;
    }

    /* Return success. */
    return ORDO_ESUCCESS;
}

int CBC_DecryptFinal(ENCRYPT_CONTEXT* ctx, unsigned char* out, size_t* outlen)
{
    unsigned char padding;

    /* If padding is disabled, we need to handle things differently. */
    if (!ctx->padding)
    {
        /* If there is data left, return an error. */
        if (cbc(ctx->ctx)->available != 0) return ORDO_LEFTOVER;

        /* Otherwise, just set the output size to zero. */
        if (outlen != 0) *outlen = 0;
    }
    else
    {
        /* Otherwise, decrypt the last block. */
        ctx->primitive->fInverse(cbc(ctx->ctx)->block, cbc(ctx->ctx)->key);

        /* Exclusive-or the last block with the running IV. */
        xorBuffer(cbc(ctx->ctx)->block, cbc(ctx->ctx)->iv, ctx->primitive->szBlock);

        /* Read the amount of padding. */
        padding = *(cbc(ctx->ctx)->block + ctx->primitive->szBlock - 1);

        /* Check the padding. */
        if ((padding != 0) && (padding <= ctx->primitive->szBlock) && (padCheck(cbc(ctx->ctx)->block + ctx->primitive->szBlock - padding, padding)))
        {
            /* Remove the padding data and output the plaintext. */
            *outlen = ctx->primitive->szBlock - padding;
            memcpy(out, cbc(ctx->ctx)->block, *outlen);
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

void CBC_Free(ENCRYPT_CONTEXT* ctx)
{
    /* Deallocate context fields. */
    sfree(cbc(ctx->ctx)->block, ctx->primitive->szBlock);
    sfree(cbc(ctx->ctx)->iv, ctx->primitive->szBlock);
    sfree(cbc(ctx->ctx)->key, ctx->primitive->szKey);
    sfree(ctx->ctx, sizeof(CBC_ENCRYPT_CONTEXT));
}

/* Fills a ENCRYPT_MODE struct with the correct information. */
void CBC_SetMode(ENCRYPT_MODE* mode)
{
    ENCRYPT_MAKEMODE(mode, CBC_Create, CBC_Init, CBC_EncryptUpdate, CBC_DecryptUpdate, CBC_EncryptFinal, CBC_DecryptFinal, CBC_Free, "CBC");
}
