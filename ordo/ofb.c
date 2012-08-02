/**
 * @file ofb.c
 * Implements the OFB mode of operation. OFB is a streaming mode of operation which performs no padding and works
 * by iterating the cipher primitive's permutation function on the initialization vector to produce the keystream
 * which is subsequently exclusive-or'ed bitwise with the plaintext to produce the ciphertext. As such, OFB
 * decryption is identical to encryption, and the cipher's inverse permutation function is not used.
 *
 * @see ofb.h
 */

#include "primitives.h"
#include "encrypt.h"
#include "ofb.h"

void OFB_Create(OFB_ENCRYPT_CONTEXT* ctx)
{
    /* Allocate context space. */
    ctx->key = salloc(ctx->primitive->szKey);
    ctx->iv = salloc(ctx->primitive->szBlock);
    ctx->reserved = salloc(sizeof(OFB_RESERVED));
}

/*! Initializes an OFB context (the primitive and mode must have been filled in).
  \param ctx The initialized encryption context.
  \param key A pointer to the key to use for encryption.
  \param keySize The size, in bytes, of the key.
  \param tweak The tweak to use (this may be zero, depending on the primitive).
  \param iv The initialization vector to use.
  \return Returns true on success, false on failure. */
int OFB_Init(OFB_ENCRYPT_CONTEXT* ctx, void* key, size_t keySize, void* tweak, void* iv)
{
    /* Check the key size. */
    if (!ctx->primitive->fKeyCheck(keySize)) return ORDO_EKEYSIZE;

    /* Copy the IV (required) into the context IV. */
    memcpy(ctx->iv, iv, ctx->primitive->szBlock);

    /* Perform the key schedule. */
    ctx->primitive->fKeySchedule(key, keySize, tweak, ctx->key);

    /* Compute the initial keystream block. */
    ctx->primitive->fForward(ctx->iv, ctx->key);
    ctx->reserved->remaining = ctx->primitive->szBlock;

    /* Return success. */
    return ORDO_ESUCCESS;
}

/*! Encrypts/decrypts a buffer in OFB mode. The context must have been allocated and initialized.
  \param ctx The initialized encryption context.
  \param in A pointer to the plaintext buffer.
  \param inlen The size of the plaintext buffer, in bytes.
  \param out A pointer to the ciphertext buffer.
  \param outlen A pointer to an integer which will contain the amount of ciphertext output, in bytes.
  \return Returns true on success, false on failure.
  \remark The out buffer must be the same size as the in buffer, as OFB is a streaming mode. */
void OFB_Update(OFB_ENCRYPT_CONTEXT* ctx, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
{
    /* Variable to store how much data can be processed per iteration. */
    size_t process = 0;

    /* Initialize the output size. */
    *outlen = 0;

    /* Go over the buffer byte per byte. */
    while (inlen != 0)
    {
        /* If there is no data left in the context block, update. */
        if (ctx->reserved->remaining == 0)
        {
            /* OFB update (simply apply the permutation function again). */
            ctx->primitive->fForward(ctx->iv, ctx->key);
            ctx->reserved->remaining = ctx->primitive->szBlock;
        }

        /* Compute the amount of data to process. */
        process = (inlen < ctx->reserved->remaining) ? inlen : ctx->reserved->remaining;

        /* Process this amount of data. */
        memcpy(out, in, process);
        xorBuffer(out, (unsigned char*)ctx->iv + ctx->primitive->szBlock - ctx->reserved->remaining, process);
        ctx->reserved->remaining -= process;
        (*outlen) += process;
        inlen -= process;
        out += process;
        in += process;
    }
}

/*! Finalizes an encryption context in OFB mode. The context must have been allocated and initialized.
  \param ctx The initialized encryption context.
  \param out Set this to zero as the OFB mode uses no padding.
  \param outlen Set this to null.
  \param decrypt Unused parameter.
  \return Returns true on success, false on failure. */
int OFB_Final(OFB_ENCRYPT_CONTEXT* ctx, unsigned char* out, size_t* outlen)
{
    /* Write output size if applicable. */
    if (outlen != 0) *outlen = 0;

    /* Return success. */
    return ORDO_ESUCCESS;
}

void OFB_Free(OFB_ENCRYPT_CONTEXT* ctx)
{
    /* Free context space. */
    sfree(ctx->reserved, sizeof(OFB_RESERVED));
    sfree(ctx->iv, ctx->primitive->szBlock);
    sfree(ctx->key, ctx->primitive->szKey);
}

/* Fills a ENCRYPT_MODE struct with the correct information. */
void OFB_SetMode(ENCRYPT_MODE* mode)
{
    ENCRYPT_MAKEMODE(mode, OFB_Create, OFB_Init, OFB_Update, OFB_Update, OFB_Final, OFB_Final, OFB_Free, "OFB");
}
