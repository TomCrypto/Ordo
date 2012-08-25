/**
 * @file ctr.c
 * Implements the CTR mode of operation. CTR is a streaming mode of operation, which performs no padding and works by
 * feeding an ever-increasing counter (initially set to the initialization vector) into the cipher's permutation to
 * produce the keystream, which is subsequently exclusive-or'ed bitwise with the plaintext to produce the ciphertext.
 * As such, CTR decryption is identical to CTR encryption, and the cipher's inverse permutation function is not used.
 *
 * @see ctr.h
 */

#include <primitives/primitives.h>
#include <encrypt/encrypt.h>
#include <encrypt/modes/ctr.h>

/*! This is extra context space required by the CTR mode to store the counter and the amount of state not used.*/
typedef struct CTR_ENCRYPT_CONTEXT
{
    /*! A buffer for the key. */
    void* key;
    /*! A buffer for the IV. */
    void* iv;
    /*! The counter value. */
    unsigned char* counter;
    /*! The amount of bytes of unused state remaining before the state is to be renewed. */
    size_t remaining;
} CTR_ENCRYPT_CONTEXT;

/*! Shorthand macro for context casting. */
#define ctr(ctx) ((CTR_ENCRYPT_CONTEXT*)ctx)

void CTR_Create(ENCRYPT_CONTEXT* ctx)
{
    /* Allocate context space. */
    ctx->ctx = salloc(sizeof(CTR_ENCRYPT_CONTEXT));
    ctr(ctx->ctx)->key = salloc(ctx->primitive->szKey);
    ctr(ctx->ctx)->iv = salloc(ctx->primitive->szBlock);
    ctr(ctx->ctx)->counter = salloc(ctx->primitive->szBlock);
}

/*! Initializes a CTR context (the primitive and mode must have been filled in).
  \param ctx The initialized encryption context.
  \param key A pointer to the key to use for encryption.
  \param keySize The size, in bytes, of the key.
  \param tweak The tweak to use (this may be zero, depending on the primitive).
  \param iv The initialization vector to use.
  \return Returns true on success, false on failure. */
int CTR_Init(ENCRYPT_CONTEXT* ctx, void* key, size_t keySize, void* tweak, void* iv, void* params)
{
    /* Check the key size. */
    if (!ctx->primitive->fKeyCheck(keySize)) return ORDO_EKEYSIZE;

    /* Copy the IV (required) into the context IV. */
    memcpy(ctr(ctx->ctx)->iv, iv, ctx->primitive->szBlock);

    /* Perform the key schedule. */
    ctx->primitive->fKeySchedule(key, keySize, tweak, ctr(ctx->ctx)->key, params);

    /* Copy the IV into the counter. */
    memcpy(ctr(ctx->ctx)->counter, ctr(ctx->ctx)->iv, ctx->primitive->szBlock);

    /* Compute the initial keystream block. */
    ctx->primitive->fForward(ctr(ctx->ctx)->iv, ctr(ctx->ctx)->key);
    ctr(ctx->ctx)->remaining = ctx->primitive->szBlock;

    /* Return success. */
    return ORDO_ESUCCESS;
}

/*! Encrypts/decrypts a buffer in CTR mode. The context must have been allocated and initialized.
  \param ctx The initialized encryption context.
  \param in A pointer to the plaintext buffer.
  \param inlen The size of the plaintext buffer, in bytes.
  \param out A pointer to the ciphertext buffer.
  \param outlen A pointer to an integer which will contain the amount of ciphertext output, in bytes.
  \remark The out buffer must be the same size as the in buffer, as CTR is a streaming mode. */
void CTR_Update(ENCRYPT_CONTEXT* ctx, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
{
    /* Variable to store how much data can be processed per iteration. */
    size_t process = 0;

    /* Initialize the output size. */
    *outlen = 0;

    /* Go over the input buffer byte per byte. */
    while (inlen != 0)
    {
        /* If there is no data left in the context block, update. */
        if (ctr(ctx->ctx)->remaining == 0)
        {
            /* CTR update (increment counter, copy counter into IV, encrypt IV). */
            incBuffer(ctr(ctx->ctx)->counter, ctx->primitive->szBlock);
            memcpy(ctr(ctx->ctx)->iv, ctr(ctx->ctx)->counter, ctx->primitive->szBlock);
            ctx->primitive->fForward(ctr(ctx->ctx)->iv, ctr(ctx->ctx)->key);
            ctr(ctx->ctx)->remaining = ctx->primitive->szBlock;
        }

        /* Compute the amount of data to process. */
        process = (inlen < ctr(ctx->ctx)->remaining) ? inlen : ctr(ctx->ctx)->remaining;

        /* Process this amount of data. */
        memmove(out, in, process);
        xorBuffer(out, (unsigned char*)ctr(ctx->ctx)->iv + ctx->primitive->szBlock - ctr(ctx->ctx)->remaining, process);
        ctr(ctx->ctx)->remaining -= process;
        (*outlen) += process;
        inlen -= process;
        out += process;
        in += process;
    }
}

/*! Finalizes an encryption context in CTR mode. The context must have been allocated and initialized.
  \param ctx The initialized encryption context.
  \param out Set this to zero as the CTR mode uses no padding.
  \param outlen Set this to null.
  \param decrypt Unused parameter.
  \return Returns true on success, false on failure. */
int CTR_Final(ENCRYPT_CONTEXT* ctx, unsigned char* out, size_t* outlen)
{
    /* Write output size if applicable. */
    if (outlen != 0) *outlen = 0;

    /* Return success. */
    return ORDO_ESUCCESS;
}

void CTR_Free(ENCRYPT_CONTEXT* ctx)
{
    /* Free context space. */
    sfree(ctr(ctx->ctx)->counter, ctx->primitive->szBlock);
    sfree(ctr(ctx->ctx)->iv, ctx->primitive->szBlock);
    sfree(ctr(ctx->ctx)->key, ctx->primitive->szKey);
    sfree(ctx->ctx, sizeof(CTR_ENCRYPT_CONTEXT));
}

/* Fills a ENCRYPT_MODE struct with the correct information. */
void CTR_SetMode(ENCRYPT_MODE* mode)
{
    ENCRYPT_MAKEMODE(mode, CTR_Create, CTR_Init, CTR_Update, CTR_Update, CTR_Final, CTR_Final, CTR_Free, "CTR");
}
