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

/*! Shorthand macro for context casting. */
#define stream(ctx) ((STREAM_ENCRYPT_CONTEXT*)ctx)

void STREAM_Create(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher)
{
    /* This mode of operation maintains no state. */
    return;
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
    /* Copy the plaintext to the ciphertext buffer. */
    memcpy(out, in, inlen);

    /* Simply generate a keystream of the right length and exclusive-or it with the plaintext. */
    cipher->primitive->fForward(cipher, out, inlen);

    /* Set the output length. */
    *outlen = inlen;
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
    /* Nothing to free... */
}

/* Fills a ENCRYPT_MODE struct with the correct information. */
void STREAM_SetMode(ENCRYPT_MODE* mode)
{
    ENCRYPT_MAKEMODE(mode, STREAM_Create, STREAM_Init, STREAM_Update, STREAM_Update, STREAM_Final, STREAM_Final, STREAM_Free, "STREAM");
}
