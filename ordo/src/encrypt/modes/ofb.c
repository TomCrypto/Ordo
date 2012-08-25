/**
 * @file ofb.c
 * Implements the OFB mode of operation. OFB is a streaming mode of operation which performs no padding and works
 * by iterating the cipher primitive's permutation function on the initialization vector to produce the keystream
 * which is subsequently exclusive-or'ed bitwise with the plaintext to produce the ciphertext. As such, OFB
 * decryption is identical to encryption, and the cipher's inverse permutation function is not used.
 *
 * @see ofb.h
 */

#include <primitives/primitives.h>
#include <encrypt/encrypt.h>
#include <encrypt/modes/ofb.h>

/*! This is extra context space required by the OFB mode to store the amount of state not used.*/
typedef struct OFB_ENCRYPT_CONTEXT
{
    /*! A buffer for the key. */
    void* key;
    /*! A buffer for the IV. */
    void* iv;
    /*! The amount of bytes of unused state remaining before the state is to be renewed. */
    size_t remaining;
} OFB_ENCRYPT_CONTEXT;

/*! Shorthand macro for context casting. */
#define ofb(ctx) ((OFB_ENCRYPT_CONTEXT*)ctx)

void OFB_Create(ENCRYPT_CONTEXT* ctx)
{
    /* Allocate context space. */
    ctx->ctx = salloc(sizeof(OFB_ENCRYPT_CONTEXT));
    ofb(ctx->ctx)->key = salloc(ctx->primitive->szKey);
    ofb(ctx->ctx)->iv = salloc(ctx->primitive->szBlock);
    ofb(ctx->ctx)->remaining = 0;
}

/*! Initializes an OFB context (the primitive and mode must have been filled in).
  \param ctx The initialized encryption context.
  \param key A pointer to the key to use for encryption.
  \param keySize The size, in bytes, of the key.
  \param tweak The tweak to use (this may be zero, depending on the primitive).
  \param iv The initialization vector to use.
  \return Returns true on success, false on failure. */
int OFB_Init(ENCRYPT_CONTEXT* ctx, void* key, size_t keySize, void* tweak, void* iv, void* params)
{
    /* Check the key size. */
    if (!ctx->primitive->fKeyCheck(keySize)) return ORDO_EKEYSIZE;

    /* Copy the IV (required) into the context IV. */
    memcpy(ofb(ctx->ctx)->iv, iv, ctx->primitive->szBlock);

    /* Perform the key schedule. */
    ctx->primitive->fKeySchedule(key, keySize, tweak, ofb(ctx->ctx)->key, params);

    /* Compute the initial keystream block. */
    ctx->primitive->fForward(ofb(ctx->ctx)->iv, ofb(ctx->ctx)->key);
    ofb(ctx->ctx)->remaining = ctx->primitive->szBlock;

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
void OFB_Update(ENCRYPT_CONTEXT* ctx, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
{
    /* Variable to store how much data can be processed per iteration. */
    size_t process = 0;

    /* Initialize the output size. */
    *outlen = 0;

    /* Go over the buffer byte per byte. */
    while (inlen != 0)
    {
        /* If there is no data left in the context block, update. */
        if (ofb(ctx->ctx)->remaining == 0)
        {
            /* OFB update (simply apply the permutation function again). */
            ctx->primitive->fForward(ofb(ctx->ctx)->iv, ofb(ctx->ctx)->key);
            ofb(ctx->ctx)->remaining = ctx->primitive->szBlock;
        }

        /* Compute the amount of data to process. */
        process = (inlen < ofb(ctx->ctx)->remaining) ? inlen : ofb(ctx->ctx)->remaining;

        /* Process this amount of data. */
        memmove(out, in, process);
        xorBuffer(out, (unsigned char*)ofb(ctx->ctx)->iv + ctx->primitive->szBlock - ofb(ctx->ctx)->remaining, process);
        ofb(ctx->ctx)->remaining -= process;
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
int OFB_Final(ENCRYPT_CONTEXT* ctx, unsigned char* out, size_t* outlen)
{
    /* Write output size if applicable. */
    if (outlen != 0) *outlen = 0;

    /* Return success. */
    return ORDO_ESUCCESS;
}

void OFB_Free(ENCRYPT_CONTEXT* ctx)
{
    /* Free context space. */
    sfree(ofb(ctx->ctx)->iv, ctx->primitive->szBlock);
    sfree(ofb(ctx->ctx)->key, ctx->primitive->szKey);
    sfree(ctx->ctx, sizeof(OFB_ENCRYPT_CONTEXT));
}

/* Fills a ENCRYPT_MODE struct with the correct information. */
void OFB_SetMode(ENCRYPT_MODE* mode)
{
    ENCRYPT_MAKEMODE(mode, OFB_Create, OFB_Init, OFB_Update, OFB_Update, OFB_Final, OFB_Final, OFB_Free, "OFB");
}
