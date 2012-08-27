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
    /*! A buffer for the IV. */
    void* iv;
    /*! The counter value. */
    unsigned char* counter;
    /*! The amount of bytes of unused state remaining before the state is to be renewed. */
    size_t remaining;
} CTR_ENCRYPT_CONTEXT;

/*! Shorthand macro for context casting. */
#define ctr(ctx) ((CTR_ENCRYPT_CONTEXT*)ctx)

void CTR_Create(ENCRYPT_MODE_CONTEXT* ctx, CIPHER_PRIMITIVE_CONTEXT* cipher)
{
    /* Allocate context space. */
    ctx->ctx = salloc(sizeof(CTR_ENCRYPT_CONTEXT));
    ctr(ctx->ctx)->iv = salloc(cipher->primitive->szBlock);
    ctr(ctx->ctx)->counter = salloc(cipher->primitive->szBlock);
}

/*! Initializes a CTR context (the primitive and mode must have been filled in).
  \param ctx The initialized encryption context.
  \param key A pointer to the key to use for encryption.
  \param keySize The size, in bytes, of the key.
  \param tweak The tweak to use (this may be zero, depending on the primitive).
  \param iv The initialization vector to use.
  \return Returns true on success, false on failure. */
int CTR_Init(ENCRYPT_MODE_CONTEXT* ctx, CIPHER_PRIMITIVE_CONTEXT* cipher, void* iv, void* params)
{
    /* Copy the IV (required) into the context IV. */
    memcpy(ctr(ctx->ctx)->iv, iv, cipher->primitive->szBlock);

    /* Copy the IV into the counter. */
    memcpy(ctr(ctx->ctx)->counter, ctr(ctx->ctx)->iv, cipher->primitive->szBlock);

    /* Compute the initial keystream block. */
    cipher->primitive->fForward(cipher, ctr(ctx->ctx)->iv);
    ctr(ctx->ctx)->remaining = cipher->primitive->szBlock;

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
void CTR_Update(ENCRYPT_MODE_CONTEXT* ctx, CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
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
            incBuffer(ctr(ctx->ctx)->counter, cipher->primitive->szBlock);
            memcpy(ctr(ctx->ctx)->iv, ctr(ctx->ctx)->counter, cipher->primitive->szBlock);
            cipher->primitive->fForward(cipher, ctr(ctx->ctx)->iv);
            ctr(ctx->ctx)->remaining = cipher->primitive->szBlock;
        }

        /* Compute the amount of data to process. */
        process = (inlen < ctr(ctx->ctx)->remaining) ? inlen : ctr(ctx->ctx)->remaining;

        /* Process this amount of data. */
        memmove(out, in, process);
        xorBuffer(out, (unsigned char*)ctr(ctx->ctx)->iv + cipher->primitive->szBlock - ctr(ctx->ctx)->remaining, process);
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
int CTR_Final(ENCRYPT_MODE_CONTEXT* ctx, CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* out, size_t* outlen)
{
    /* Write output size if applicable. */
    if (outlen != 0) *outlen = 0;

    /* Return success. */
    return ORDO_ESUCCESS;
}

void CTR_Free(ENCRYPT_MODE_CONTEXT* ctx, CIPHER_PRIMITIVE_CONTEXT* cipher)
{
    /* Free context space. */
    sfree(ctr(ctx->ctx)->counter, cipher->primitive->szBlock);
    sfree(ctr(ctx->ctx)->iv, cipher->primitive->szBlock);
    sfree(ctx->ctx, sizeof(CTR_ENCRYPT_CONTEXT));
}

/* Fills a ENCRYPT_MODE struct with the correct information. */
void CTR_SetMode(ENCRYPT_MODE* mode)
{
    ENCRYPT_MAKEMODE(mode, CTR_Create, CTR_Init, CTR_Update, CTR_Update, CTR_Final, CTR_Final, CTR_Free, "CTR");
}
