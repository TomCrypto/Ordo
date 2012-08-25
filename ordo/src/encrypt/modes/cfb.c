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

/*! This is extra context space required by the CFB mode to store the amount of state not used.*/
typedef struct CFB_ENCRYPT_CONTEXT
{
    /*! A buffer for the key. */
    void* key;
    /*! A buffer for the IV. */
    void* iv;
    /*! The amount of bytes of unused state remaining before the state is to be renewed. */
    size_t remaining;
} CFB_ENCRYPT_CONTEXT;

/*! Shorthand macro for context casting. */
#define cfb(ctx) ((CFB_ENCRYPT_CONTEXT*)ctx)

void CFB_Create(ENCRYPT_CONTEXT* ctx)
{
    /* Allocate context space. */
    ctx->ctx = salloc(sizeof(CFB_ENCRYPT_CONTEXT));
    cfb(ctx->ctx)->key = salloc(ctx->primitive->szKey);
    cfb(ctx->ctx)->iv = salloc(ctx->primitive->szBlock);
    cfb(ctx->ctx)->remaining = 0;
}

/*! Initializes an OFB context (the primitive and mode must have been filled in).
  \param ctx The initialized encryption context.
  \param key A pointer to the key to use for encryption.
  \param keySize The size, in bytes, of the key.
  \param tweak The tweak to use (this may be zero, depending on the primitive).
  \param iv The initialization vector to use.
  \return Returns true on success, false on failure. */
int CFB_Init(ENCRYPT_CONTEXT* ctx, void* key, size_t keySize, void* tweak, void* iv, void* params)
{
    /* Check the key size. */
    if (!ctx->primitive->fKeyCheck(keySize)) return ORDO_EKEYSIZE;

    /* Copy the IV (required) into the context IV. */
    memcpy(cfb(ctx->ctx)->iv, iv, ctx->primitive->szBlock);

    /* Perform the key schedule. */
    ctx->primitive->fKeySchedule(key, keySize, tweak, cfb(ctx->ctx)->key, params);

    /* Compute the initial keystream block. */
    ctx->primitive->fForward(cfb(ctx->ctx)->iv, cfb(ctx->ctx)->key);
    cfb(ctx->ctx)->remaining = ctx->primitive->szBlock;

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
void CFB_EncryptUpdate(ENCRYPT_CONTEXT* ctx, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
{
    /* Variable to store how much data can be processed per iteration. */
    size_t process = 0;

    /* Initialize the output size. */
    *outlen = 0;

    /* Go over the buffer byte per byte. */
    while (inlen != 0)
    {
        /* If there is no data left in the context block, update. */
        if (cfb(ctx->ctx)->remaining == 0)
        {
            /* CFB update (simply apply the permutation function again). */
            ctx->primitive->fForward(cfb(ctx->ctx)->iv, cfb(ctx->ctx)->key);
            cfb(ctx->ctx)->remaining = ctx->primitive->szBlock;
        }

        /* Compute the amount of data to process. */
        process = (inlen < cfb(ctx->ctx)->remaining) ? inlen : cfb(ctx->ctx)->remaining;

        /* Process this amount of data. */
        memmove(out, in, process);
        xorBuffer(out, (unsigned char*)cfb(ctx->ctx)->iv + ctx->primitive->szBlock - cfb(ctx->ctx)->remaining, process);
        memcpy((unsigned char*)cfb(ctx->ctx)->iv + ctx->primitive->szBlock - cfb(ctx->ctx)->remaining, out, process);
        cfb(ctx->ctx)->remaining -= process;
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
void CFB_DecryptUpdate(ENCRYPT_CONTEXT* ctx, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
{
    /* Variable to store how much data can be processed per iteration. */
    size_t process = 0;

    /* Initialize the output size. */
    *outlen = 0;

    /* Go over the buffer byte per byte. */
    while (inlen != 0)
    {
        /* If there is no data left in the context block, update. */
        if (cfb(ctx->ctx)->remaining == 0)
        {
            /* CFB update (simply apply the permutation function again). */
            ctx->primitive->fForward(cfb(ctx->ctx)->iv, cfb(ctx->ctx)->key);
            cfb(ctx->ctx)->remaining = ctx->primitive->szBlock;
        }

        /* Compute the amount of data to process. */
        process = (inlen < cfb(ctx->ctx)->remaining) ? inlen : cfb(ctx->ctx)->remaining;

        /* Process this amount of data. */
        memmove(out, in, process);
        xorBuffer(out, (unsigned char*)cfb(ctx->ctx)->iv + ctx->primitive->szBlock - cfb(ctx->ctx)->remaining, process);
        memcpy((unsigned char*)cfb(ctx->ctx)->iv + ctx->primitive->szBlock - cfb(ctx->ctx)->remaining, in, process);
        cfb(ctx->ctx)->remaining -= process;
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
int CFB_Final(ENCRYPT_CONTEXT* ctx, unsigned char* out, size_t* outlen)
{
    /* Write output size if applicable. */
    if (outlen != 0) *outlen = 0;

    /* Return success. */
    return ORDO_ESUCCESS;
}

void CFB_Free(ENCRYPT_CONTEXT* ctx)
{
    /* Free context space. */
    sfree(cfb(ctx->ctx)->iv, ctx->primitive->szBlock);
    sfree(cfb(ctx->ctx)->key, ctx->primitive->szKey);
    sfree(ctx->ctx, sizeof(CFB_ENCRYPT_CONTEXT));
}

/* Fills a ENCRYPT_MODE struct with the correct information. */
void CFB_SetMode(ENCRYPT_MODE* mode)
{
    ENCRYPT_MAKEMODE(mode, CFB_Create, CFB_Init, CFB_EncryptUpdate, CFB_DecryptUpdate, CFB_Final, CFB_Final, CFB_Free, "CFB");
}
