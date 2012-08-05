/**
 * @file cfb.c
 * Implements the CFB mode of operation. CFB is a streaming mode of operation which performs no padding and works
 * similarly to the OFB mode of operation, except the keystream is exclusive-or'ed with the plaintext before being
 * fed back into the permutation function (whereas OFB is fed back immediately). Therefore the CFB keystream is
 * dependent on the plaintext.
 *
 * @see cfb.h
 */

#include <primitives/primitives.h>
#include <encrypt/encrypt.h>
#include <encrypt/modes/cfb.h>

void CFB_Create(CFB_ENCRYPT_CONTEXT* ctx)
{
    /* Allocate context space. */
    ctx->key = salloc(ctx->primitive->szKey);
    ctx->iv = salloc(ctx->primitive->szBlock);
    ctx->reserved = salloc(sizeof(CFB_RESERVED));
}

/*! Initializes an OFB context (the primitive and mode must have been filled in).
  \param ctx The initialized encryption context.
  \param key A pointer to the key to use for encryption.
  \param keySize The size, in bytes, of the key.
  \param tweak The tweak to use (this may be zero, depending on the primitive).
  \param iv The initialization vector to use.
  \return Returns true on success, false on failure. */
int CFB_Init(CFB_ENCRYPT_CONTEXT* ctx, void* key, size_t keySize, void* tweak, void* iv)
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

/*! Encrypts a buffer in OFB mode. The context must have been allocated and initialized.
  \param ctx The initialized encryption context.
  \param in A pointer to the plaintext buffer.
  \param inlen The size of the plaintext buffer, in bytes.
  \param out A pointer to the ciphertext buffer.
  \param outlen A pointer to an integer which will contain the amount of ciphertext output, in bytes.
  \remark The out buffer must be the same size as the in buffer, as OFB is a streaming mode. */
void CFB_EncryptUpdate(CFB_ENCRYPT_CONTEXT* ctx, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
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
            /* CFB update (simply apply the permutation function again). */
            ctx->primitive->fForward(ctx->iv, ctx->key);
            ctx->reserved->remaining = ctx->primitive->szBlock;
        }

        /* Compute the amount of data to process. */
        process = (inlen < ctx->reserved->remaining) ? inlen : ctx->reserved->remaining;

        /* Process this amount of data. */
        memmove(out, in, process);
        xorBuffer(out, (unsigned char*)ctx->iv + ctx->primitive->szBlock - ctx->reserved->remaining, process);
        memcpy((unsigned char*)ctx->iv + ctx->primitive->szBlock - ctx->reserved->remaining, out, process);
        ctx->reserved->remaining -= process;
        (*outlen) += process;
        inlen -= process;
        out += process;
        in += process;
    }
}

/*! Decrypts a buffer in OFB mode. The context must have been allocated and initialized.
  \param ctx The initialized encryption context.
  \param in A pointer to the ciphertext buffer.
  \param inlen The size of the ciphertext buffer, in bytes.
  \param out A pointer to the plaintext buffer.
  \param outlen A pointer to an integer which will contain the amount of plaintext output, in bytes.
  \remark The out buffer must be the same size as the in buffer, as OFB is a streaming mode.  */
void CFB_DecryptUpdate(CFB_ENCRYPT_CONTEXT* ctx, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
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
            /* CFB update (simply apply the permutation function again). */
            ctx->primitive->fForward(ctx->iv, ctx->key);
            ctx->reserved->remaining = ctx->primitive->szBlock;
        }

        /* Compute the amount of data to process. */
        process = (inlen < ctx->reserved->remaining) ? inlen : ctx->reserved->remaining;

        /* Process this amount of data. */
        memmove(out, in, process);
        xorBuffer(out, (unsigned char*)ctx->iv + ctx->primitive->szBlock - ctx->reserved->remaining, process);
        memcpy((unsigned char*)ctx->iv + ctx->primitive->szBlock - ctx->reserved->remaining, in, process);
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
int CFB_Final(CFB_ENCRYPT_CONTEXT* ctx, unsigned char* out, size_t* outlen)
{
    /* Write output size if applicable. */
    if (outlen != 0) *outlen = 0;

    /* Return success. */
    return ORDO_ESUCCESS;
}

void CFB_Free(CFB_ENCRYPT_CONTEXT* ctx)
{
    /* Free context space. */
    sfree(ctx->reserved, sizeof(CFB_RESERVED));
    sfree(ctx->iv, ctx->primitive->szBlock);
    sfree(ctx->key, ctx->primitive->szKey);
}

/* Fills a ENCRYPT_MODE struct with the correct information. */
void CFB_SetMode(ENCRYPT_MODE* mode)
{
    ENCRYPT_MAKEMODE(mode, CFB_Create, CFB_Init, CFB_EncryptUpdate, CFB_DecryptUpdate, CFB_Final, CFB_Final, CFB_Free, "CFB");
}
