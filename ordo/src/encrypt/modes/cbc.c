/**
 * @file cbc.c
 * Implements the CBC mode of operation. The CBC mode is a block mode of operation, meaning that it performs
 * padding. It works by taking each block and XORing it with the IV. That ciphertext block then becomes the
 * IV for the next block to encrypt. Decryption is done by inverting this process. The padding algorithm is
 * PKCS7 (RFC 5652), which appends N bytes of value N, where N is the number of padding bytes required
 * (between 1 and the cipher's block size in bytes).
 *
 * @see cbc.h
 */

#include <primitives/primitives.h>
#include <encrypt/encrypt.h>
#include <encrypt/modes/cbc.h>

/*! This is extra context space required by the ECB mode to store temporary incomplete data buffers.*/
typedef struct CBC_ENCRYPT_CONTEXT
{
    /*! A buffer for the IV. */
    void* iv;
    /*! The temporary block, the size of the primitive's block size. */
    unsigned char* block;
    /*! The amount of bytes of plaintext or ciphertext currently in the temporary block. */
    size_t available;
} CBC_ENCRYPT_CONTEXT;

/*! Shorthand macro for context casting. */
#define cbc(ctx) ((CBC_ENCRYPT_CONTEXT*)ctx)

void CBC_Create(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher)
{
    /* Allocate context fields. */
    mode->ctx = salloc(sizeof(CBC_ENCRYPT_CONTEXT));
    cbc(mode->ctx)->iv = salloc(cipher->primitive->szBlock);
    cbc(mode->ctx)->block = salloc(cipher->primitive->szBlock);
    cbc(mode->ctx)->available = 0;
}

/*! Initializes an CBC context (the primitive and mode must have been filled in).
  \param context The initialized encryption context.
  \param key A pointer to the key to use for encryption.
  \param keySize The size, in bytes, of the key.
  \param tweak The tweak to use (this may be zero, depending on the primitive).
  \param iv A pointer to the IV to use for encryption.
  \return Returns 0 on success, and a negative value on failure. Possible errors are:
  ORDO_EKEYSIZE: the key size is not valid for the context's primitive. */
int CBC_Init(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, void* iv, void* params)
{
    /* Copy the IV (required) into the context IV. */
    memcpy(cbc(mode->ctx)->iv, iv, cipher->primitive->szBlock);

    /* Return success. */
    return ORDO_ESUCCESS;
}

/*! Encrypts a buffer in CBC mode. The context must have been allocated and initialized.
  \param context The initialized encryption context.
  \param in A pointer to the plaintext buffer.
  \param inlen The size of the plaintext buffer, in bytes.
  \param out A pointer to the ciphertext buffer.
  \param outlen A pointer to an integer which will contain the amount of ciphertext output, in bytes.
  \return Returns true on success, false on failure.
  \remark The out buffer must have enough space to accomodate up to one more block size of ciphertext than plaintext, rounded down to the nearest block. */
void CBC_EncryptUpdate(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
{
    /* Initialize output size. */
    *outlen = 0;

    /* Process all full blocks. */
    while (cbc(mode->ctx)->available + inlen >= cipher->primitive->szBlock)
    {
        /* Copy it in, and process it. */
        memcpy(cbc(mode->ctx)->block + cbc(mode->ctx)->available, in, cipher->primitive->szBlock - cbc(mode->ctx)->available);

        /* Exclusive-or the plaintext block with the running IV. */
        xorBuffer(cbc(mode->ctx)->block, cbc(mode->ctx)->iv, cipher->primitive->szBlock);

        /* Encrypt the block. */
        cipher->primitive->fForward(cipher, cbc(mode->ctx)->block);

        /* Set this as the new running IV. */
        memcpy(cbc(mode->ctx)->iv, cbc(mode->ctx)->block, cipher->primitive->szBlock);

        /* Write back the block to the output. */
        memcpy(out, cbc(mode->ctx)->block, cipher->primitive->szBlock);
        *outlen += cipher->primitive->szBlock;
        out += cipher->primitive->szBlock;

        /* Go forward in the input buffer. */
        inlen -= cipher->primitive->szBlock - cbc(mode->ctx)->available;
        in += cipher->primitive->szBlock - cbc(mode->ctx)->available;
        cbc(mode->ctx)->available = 0;
    }

    /* Add whatever is left in the temporary buffer. */
    memcpy(cbc(mode->ctx)->block + cbc(mode->ctx)->available, in, inlen);
    cbc(mode->ctx)->available += inlen;
}

/*! Decrypts a buffer in CBC mode. The context must have been allocated and initialized.
  \param context The initialized encryption context.
  \param in A pointer to the ciphertext buffer.
  \param inlen The size of the ciphertext buffer, in bytes.
  \param out A pointer to the plaintext buffer.
  \param outlen A pointer to an integer which will contain the amount of plaintext output, in bytes.
  \remark The out buffer must have enough space to accomodate up to one more block size of plaintext than ciphertext, rounded down to the nearest block. */
void CBC_DecryptUpdate(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
{
    /* Initialize output size. */
    *outlen = 0;

    /* Process all full blocks except the last potential block (if padding is disabled, also process the last block). */
    while (cbc(mode->ctx)->available + inlen > cipher->primitive->szBlock - (1 - mode->padding))
    {
        /* Copy it in, and process it. */
        memcpy(cbc(mode->ctx)->block + cbc(mode->ctx)->available, in, cipher->primitive->szBlock - cbc(mode->ctx)->available);

        /* Save this ciphertext block. */
        memcpy(out, cbc(mode->ctx)->block, cipher->primitive->szBlock);

        /* Decrypt the block. */
        cipher->primitive->fInverse(cipher, cbc(mode->ctx)->block);

        /* Exclusive-or the block with the running IV. */
        xorBuffer(cbc(mode->ctx)->block, cbc(mode->ctx)->iv, cipher->primitive->szBlock);

        /* Get the original ciphertext back as running IV. */
        memcpy(cbc(mode->ctx)->iv, out, cipher->primitive->szBlock);

        /* Write back the block to the output. */
        memcpy(out, cbc(mode->ctx)->block, cipher->primitive->szBlock);
        *outlen += cipher->primitive->szBlock;
        out += cipher->primitive->szBlock;

        /* Go forward in the input buffer. */
        inlen -= cipher->primitive->szBlock - cbc(mode->ctx)->available;
        in += cipher->primitive->szBlock - cbc(mode->ctx)->available;
        cbc(mode->ctx)->available = 0;
    }

    /* Save the final block. */
    memcpy(cbc(mode->ctx)->block + cbc(mode->ctx)->available, in, inlen);
    cbc(mode->ctx)->available += inlen;
}

/*! Finalizes an encryption context in CBC mode. The context must have been allocated and initialized.
  \param context The initialized encryption context.
  \param out A pointer to the final plaintext/ciphertext buffer.
  \param outlen A pointer to an integer which will contain the amount of plaintext output, in bytes.
  \return Returns true on success, false on failure.
  \remark The out buffer must have enough space to accomodate up to one block size of plaintext for padding. */
int CBC_EncryptFinal(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* out, size_t* outlen)
{
    unsigned char padding;

    /* If padding is disabled, we need to handle things differently. */
    if (mode->padding == 0)
    {
        /* If there is data left, return an error. */
        if (cbc(mode->ctx)->available != 0) return ORDO_LEFTOVER;

        /* Otherwise, just set the output size to zero. */
        if (outlen != 0) *outlen = 0;
    }
    else
    {
        /* Compute the amount of padding required. */
        padding = cipher->primitive->szBlock - cbc(mode->ctx)->available % cipher->primitive->szBlock;

        /* Write padding to the last block. */
        memset(cbc(mode->ctx)->block + cbc(mode->ctx)->available, padding, padding);

        /* Exclusive-or the last block with the running IV. */
        xorBuffer(cbc(mode->ctx)->block, cbc(mode->ctx)->iv, cipher->primitive->szBlock);

        /* Encrypt the last block. */
        cipher->primitive->fForward(cipher, cbc(mode->ctx)->block);

        /* Write it out to the buffer. */
        memcpy(out, cbc(mode->ctx)->block, cipher->primitive->szBlock);
        *outlen = cipher->primitive->szBlock;
    }

    /* Return success. */
    return ORDO_ESUCCESS;
}

int CBC_DecryptFinal(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* out, size_t* outlen)
{
    unsigned char padding;

    /* If padding is disabled, we need to handle things differently. */
    if (!mode->padding)
    {
        /* If there is data left, return an error. */
        if (cbc(mode->ctx)->available != 0) return ORDO_LEFTOVER;

        /* Otherwise, just set the output size to zero. */
        if (outlen != 0) *outlen = 0;
    }
    else
    {
        /* Otherwise, decrypt the last block. */
        cipher->primitive->fInverse(cipher, cbc(mode->ctx)->block);

        /* Exclusive-or the last block with the running IV. */
        xorBuffer(cbc(mode->ctx)->block, cbc(mode->ctx)->iv, cipher->primitive->szBlock);

        /* Read the amount of padding. */
        padding = *(cbc(mode->ctx)->block + cipher->primitive->szBlock - 1);

        /* Check the padding. */
        if ((padding != 0) && (padding <= cipher->primitive->szBlock) && (padCheck(cbc(mode->ctx)->block + cipher->primitive->szBlock - padding, padding)))
        {
            /* Remove the padding data and output the plaintext. */
            *outlen = cipher->primitive->szBlock - padding;
            memcpy(out, cbc(mode->ctx)->block, *outlen);
        }
        else
        {
            *outlen = 0;
            return ORDO_EPADDING;
        }
    }

    /* Return success. */
    return ORDO_ESUCCESS;
}

void CBC_Free(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher)
{
    /* Deallocate context fields. */
    sfree(cbc(mode->ctx)->block, cipher->primitive->szBlock);
    sfree(cbc(mode->ctx)->iv, cipher->primitive->szBlock);
    sfree(mode->ctx, sizeof(CBC_ENCRYPT_CONTEXT));
}

/* Fills a ENCRYPT_MODE struct with the correct information. */
void CBC_SetMode(ENCRYPT_MODE* mode)
{
    ENCRYPT_MAKEMODE(mode, CBC_Create, CBC_Init, CBC_EncryptUpdate, CBC_DecryptUpdate, CBC_EncryptFinal, CBC_DecryptFinal, CBC_Free, "CBC");
}
