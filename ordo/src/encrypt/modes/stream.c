/**
 * @file stream.c
 * Implements the STREAM mode of operation. STREAM is a streaming mode of operation which is only compatible with
 * stream ciphers (such as RC4). It uses no initialization vector, and does not use padding.
 *
 * @see stream.h
 */

#include <primitives/primitives.h>
#include <encrypt/encrypt.h>
#include <encrypt/modes/stream.h>

/*! This is extra context space required by the STREAM mode to store the counter and the amount of state not used.*/
typedef struct STREAM_ENCRYPT_CONTEXT
{
    /*! The keystream buffer. */
    void* keystream;
    /*! The amount of bytes of unused state remaining before the state is to be renewed. */
    size_t remaining;
} STREAM_ENCRYPT_CONTEXT;

/*! Shorthand macro for context casting. */
#define stream(ctx) ((STREAM_ENCRYPT_CONTEXT*)ctx)

void STREAM_Create(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher)
{
    /* Allocate context space. */
    mode->ctx = salloc(sizeof(STREAM_ENCRYPT_CONTEXT));
    stream(mode->ctx)->keystream = salloc(cipher->primitive->szBlock);
    stream(mode->ctx)->remaining = 0;
}

/*! Initializes a STREAM context (the primitive and mode must have been filled in).
  \param ctx The initialized encryption context.
  \param key A pointer to the key to use for encryption.
  \param keySize The size, in bytes, of the key.
  \param tweak The tweak to use (this may be zero, depending on the primitive).
  \param iv The initialization vector to use.
  \return Returns true on success, false on failure. */
int STREAM_Init(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, void* iv, void* params)
{
    /* Compute the initial keystream block. */
    cipher->primitive->fForward(cipher, stream(mode->ctx)->keystream);
    stream(mode->ctx)->remaining = cipher->primitive->szBlock;

    /* Return success. */
    return ORDO_ESUCCESS;
}

/*! Encrypts/decrypts a buffer in STREAM mode. The context must have been allocated and initialized.
  \param ctx The initialized encryption context.
  \param in A pointer to the plaintext buffer.
  \param inlen The size of the plaintext buffer, in bytes.
  \param out A pointer to the ciphertext buffer.
  \param outlen A pointer to an integer which will contain the amount of ciphertext output, in bytes.
  \return Returns true on success, false on failure.
  \remark The out buffer must be the same size as the in buffer, as STREAM is a streaming mode. */
void STREAM_Update(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
{
    /* Variable to store how much data can be processed per iteration. */
    size_t process = 0;

    /* Initialize the output size. */
    *outlen = 0;

    /* Go over the input buffer byte per byte. */
    while (inlen != 0)
    {
        /* If there is no data left in the context block, update. */
        if (stream(mode->ctx)->remaining == 0)
        {
            /* STREAM update (simply renew the state). */
            cipher->primitive->fForward(cipher, stream(mode->ctx)->keystream);
            stream(mode->ctx)->remaining = cipher->primitive->szBlock;
        }

        /* Compute the amount of data to process. */
        process = (inlen < stream(mode->ctx)->remaining) ? inlen : stream(mode->ctx)->remaining;

        /* Process this amount of data. */
        memmove(out, in, process);
        xorBuffer(out, (unsigned char*)stream(mode->ctx)->keystream + cipher->primitive->szBlock - stream(mode->ctx)->remaining, process);
        stream(mode->ctx)->remaining -= process;
        *outlen += process;
        inlen -= process;
        out += process;
        in += process;
    }
}

/*! Finalizes an encryption context in STREAM mode. The context must have been allocated and initialized.
  \param ctx The initialized encryption context.
  \param out Set this to zero as the STREAM mode uses no padding.
  \param outlen Set this to null.
  \param decrypt Unused parameter.
  \return Returns true on success, false on failure. */
int STREAM_Final(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* out, size_t* outlen)
{
    /* Write output size if applicable. */
    if (outlen != 0) *outlen = 0;

    /* Return success. */
    return ORDO_ESUCCESS;
}

void STREAM_Free(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher)
{
    /* Free context space. */
    sfree(stream(mode->ctx)->keystream, cipher->primitive->szBlock);
    sfree(mode->ctx, sizeof(STREAM_ENCRYPT_CONTEXT));
}

/* Fills a ENCRYPT_MODE struct with the correct information. */
void STREAM_SetMode(ENCRYPT_MODE* mode)
{
    ENCRYPT_MAKEMODE(mode, STREAM_Create, STREAM_Init, STREAM_Update, STREAM_Update, STREAM_Final, STREAM_Final, STREAM_Free, "STREAM");
}
