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
    /*! A buffer for the IV. */
    void* iv;
    /*! The amount of bytes of unused state remaining before the state is to be renewed. */
    size_t remaining;
} OFB_ENCRYPT_CONTEXT;

/*! Shorthand macro for context casting. */
#define ofb(ctx) ((OFB_ENCRYPT_CONTEXT*)ctx)

void OFB_Create(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher)
{
    /* Allocate context space. */
    mode->ctx = salloc(sizeof(OFB_ENCRYPT_CONTEXT));
    ofb(mode->ctx)->iv = salloc(cipher->primitive->szBlock);
    ofb(mode->ctx)->remaining = 0;
}

/*! Initializes an OFB context (the primitive and mode must have been filled in).
  \param ctx The initialized encryption context.
  \param key A pointer to the key to use for encryption.
  \param keySize The size, in bytes, of the key.
  \param tweak The tweak to use (this may be zero, depending on the primitive).
  \param iv The initialization vector to use.
  \return Returns true on success, false on failure. */
int OFB_Init(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, void* iv, void* params)
{
    /* Copy the IV (required) into the context IV. */
    memcpy(ofb(mode->ctx)->iv, iv, cipher->primitive->szBlock);

    /* Compute the initial keystream block. */
    cipher->primitive->fForward(cipher, ofb(mode->ctx)->iv);
    ofb(mode->ctx)->remaining = cipher->primitive->szBlock;

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
void OFB_Update(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
{
    /* Variable to store how much data can be processed per iteration. */
    size_t process = 0;

    /* Initialize the output size. */
    *outlen = 0;

    /* Go over the buffer byte per byte. */
    while (inlen != 0)
    {
        /* If there is no data left in the context block, update. */
        if (ofb(mode->ctx)->remaining == 0)
        {
            /* OFB update (simply apply the permutation function again). */
            cipher->primitive->fForward(cipher, ofb(mode->ctx)->iv);
            ofb(mode->ctx)->remaining = cipher->primitive->szBlock;
        }

        /* Compute the amount of data to process. */
        process = (inlen < ofb(mode->ctx)->remaining) ? inlen : ofb(mode->ctx)->remaining;

        /* Process this amount of data. */
        memmove(out, in, process);
        xorBuffer(out, (unsigned char*)ofb(mode->ctx)->iv + cipher->primitive->szBlock - ofb(mode->ctx)->remaining, process);
        ofb(mode->ctx)->remaining -= process;
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
int OFB_Final(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* out, size_t* outlen)
{
    /* Write output size if applicable. */
    if (outlen != 0) *outlen = 0;

    /* Return success. */
    return ORDO_ESUCCESS;
}

void OFB_Free(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher)
{
    /* Free context space. */
    sfree(ofb(mode->ctx)->iv, cipher->primitive->szBlock);
    sfree(mode->ctx, sizeof(OFB_ENCRYPT_CONTEXT));
}

/* Fills a ENCRYPT_MODE struct with the correct information. */
void OFB_SetMode(ENCRYPT_MODE* mode)
{
    ENCRYPT_MAKEMODE(mode, OFB_Create, OFB_Init, OFB_Update, OFB_Update, OFB_Final, OFB_Final, OFB_Free, "OFB");
}
