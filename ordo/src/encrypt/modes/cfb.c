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
    /*! A buffer for the IV. */
    void* iv;
    /*! The amount of bytes of unused state remaining before the state is to be renewed. */
    size_t remaining;
} CFB_ENCRYPT_CONTEXT;

/*! Shorthand macro for context casting. */
#define cfb(ctx) ((CFB_ENCRYPT_CONTEXT*)ctx)

void CFB_Create(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher)
{
    /* Allocate context space. */
    mode->ctx = salloc(sizeof(CFB_ENCRYPT_CONTEXT));
    cfb(mode->ctx)->iv = salloc(cipher->primitive->szBlock);
    cfb(mode->ctx)->remaining = 0;
}

/*! Initializes an OFB context (the primitive and mode must have been filled in).
  \param ctx The initialized encryption context.
  \param key A pointer to the key to use for encryption.
  \param keySize The size, in bytes, of the key.
  \param tweak The tweak to use (this may be zero, depending on the primitive).
  \param iv The initialization vector to use.
  \return Returns true on success, false on failure. */
int CFB_Init(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, void* iv, void* params)
{
    /* Copy the IV (required) into the context IV. */
    memcpy(cfb(mode->ctx)->iv, iv, cipher->primitive->szBlock);

    /* Compute the initial keystream block. */
    cipher->primitive->fForward(cipher, cfb(mode->ctx)->iv, cipher->primitive->szBlock);
    cfb(mode->ctx)->remaining = cipher->primitive->szBlock;

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
void CFB_EncryptUpdate(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
{
    /* Variable to store how much data can be processed per iteration. */
    size_t process = 0;

    /* Initialize the output size. */
    *outlen = 0;

    /* Go over the buffer byte per byte. */
    while (inlen != 0)
    {
        /* If there is no data left in the context block, update. */
        if (cfb(mode->ctx)->remaining == 0)
        {
            /* CFB update (simply apply the permutation function again). */
            cipher->primitive->fForward(cipher, cfb(mode->ctx)->iv, cipher->primitive->szBlock);
            cfb(mode->ctx)->remaining = cipher->primitive->szBlock;
        }

        /* Compute the amount of data to process. */
        process = (inlen < cfb(mode->ctx)->remaining) ? inlen : cfb(mode->ctx)->remaining;

        /* Process this amount of data. */
        memmove(out, in, process);
        xorBuffer(out, (unsigned char*)cfb(mode->ctx)->iv + cipher->primitive->szBlock - cfb(mode->ctx)->remaining, process);
        memcpy((unsigned char*)cfb(mode->ctx)->iv + cipher->primitive->szBlock - cfb(mode->ctx)->remaining, out, process);
        cfb(mode->ctx)->remaining -= process;
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
void CFB_DecryptUpdate(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
{
    /* Variable to store how much data can be processed per iteration. */
    size_t process = 0;

    /* Initialize the output size. */
    *outlen = 0;

    /* Go over the buffer byte per byte. */
    while (inlen != 0)
    {
        /* If there is no data left in the context block, update. */
        if (cfb(mode->ctx)->remaining == 0)
        {
            /* CFB update (simply apply the permutation function again). */
            cipher->primitive->fForward(cipher, cfb(mode->ctx)->iv, cipher->primitive->szBlock);
            cfb(mode->ctx)->remaining = cipher->primitive->szBlock;
        }

        /* Compute the amount of data to process. */
        process = (inlen < cfb(mode->ctx)->remaining) ? inlen : cfb(mode->ctx)->remaining;

        /* Process this amount of data. */
        memmove(out, in, process);
        xorBuffer(out, (unsigned char*)cfb(mode->ctx)->iv + cipher->primitive->szBlock - cfb(mode->ctx)->remaining, process);
        memcpy((unsigned char*)cfb(mode->ctx)->iv + cipher->primitive->szBlock - cfb(mode->ctx)->remaining, in, process);
        cfb(mode->ctx)->remaining -= process;
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
int CFB_Final(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* out, size_t* outlen)
{
    /* Write output size if applicable. */
    if (outlen != 0) *outlen = 0;

    /* Return success. */
    return ORDO_ESUCCESS;
}

void CFB_Free(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher)
{
    /* Free context space. */
    sfree(cfb(mode->ctx)->iv, cipher->primitive->szBlock);
    sfree(mode->ctx, sizeof(CFB_ENCRYPT_CONTEXT));
}

/* Fills a ENCRYPT_MODE struct with the correct information. */
void CFB_SetMode(ENCRYPT_MODE* mode)
{
    ENCRYPT_MAKEMODE(mode, CFB_Create, CFB_Init, CFB_EncryptUpdate, CFB_DecryptUpdate, CFB_Final, CFB_Final, CFB_Free, "CFB");
}
