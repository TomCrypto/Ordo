/**
 * @file ecb.c
 * Implements the ECB mode of operation. The ECB mode is a block mode of operation, meaning that it performs
 * padding. It works by taking each block and feeding it into the permutation function, taking the output
 * as the ciphertext. To decrypt, the ciphertext it passed through the inverse permutation function to recover
 * the plaintext. The padding algorithm is PKCS7 (RFC 5652), which appends N bytes of value N, where N is the
 * number of padding bytes required (between 1 and the cipher's block size in bytes).
 *
 * Note that the ECB mode is generally insecure and is not recommended for use.
 *
 * @see ecb.h
 */

#include <primitives/primitives.h>
#include <encrypt/encrypt.h>
#include <encrypt/modes/ecb.h>

/*! This is extra context space required by the ECB mode to store temporary incomplete data buffers.*/
typedef struct ECB_ENCRYPT_CONTEXT
{
    /*! The temporary block, the size of the primitive's block size. */
    unsigned char* block;
    /*! The amount of bytes of plaintext or ciphertext currently in the temporary block. */
    size_t available;
} ECB_ENCRYPT_CONTEXT;

/*! Shorthand macro for context casting. */
#define ecb(ctx) ((ECB_ENCRYPT_CONTEXT*)ctx)

void ECB_Create(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher)
{
    /* Allocate context fields. */
    mode->ctx = salloc(sizeof(ECB_ENCRYPT_CONTEXT));
    ecb(mode->ctx)->block = salloc(cipher->primitive->szBlock);
    ecb(mode->ctx)->available = 0;
}

/*! Initializes an ECB context (the primitive and mode must have been filled in).
  \param context The initialized encryption context.
  \param key A pointer to the key to use for encryption.
  \param keySize The size, in bytes, of the key.
  \param tweak The tweak to use (this may be zero, depending on the primitive).
  \param iv Set this to zero, as the ECB mode uses no initialization vector.
  \return Returns 0 on success, and a negative value on failure. Possible errors are:
  ORDO_EKEYSIZE: the key size is not valid for the context's primitive. */
int ECB_Init(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, void* iv, void* params)
{
    /* Return success. */
    return ORDO_ESUCCESS;
}

/*! Encrypts a buffer in ECB mode. The context must have been allocated and initialized.
  \param context The initialized encryption context.
  \param in A pointer to the plaintext buffer.
  \param inlen The size of the plaintext buffer, in bytes.
  \param out A pointer to the ciphertext buffer.
  \param outlen A pointer to an integer which will contain the amount of ciphertext output, in bytes.
  \return Returns true on success, false on failure.
  \remark The out buffer must have enough space to accomodate up to one more block size of ciphertext than plaintext, rounded down to the nearest block. */
void ECB_EncryptUpdate(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
{
    /* Initialize output size. */
    *outlen = 0;

    /* Process all full blocks. */
    while (ecb(mode->ctx)->available + inlen >= cipher->primitive->szBlock)
    {
        /* Copy it in, and process it. */
        memcpy(ecb(mode->ctx)->block + ecb(mode->ctx)->available, in, cipher->primitive->szBlock - ecb(mode->ctx)->available);

        /* Encrypt the block. */
        cipher->primitive->fForward(cipher, ecb(mode->ctx)->block);

        /* Write back the block to the output. */
        memcpy(out, ecb(mode->ctx)->block, cipher->primitive->szBlock);
        *outlen += cipher->primitive->szBlock;
        out += cipher->primitive->szBlock;

        /* Go forward in the input buffer. */
        inlen -= cipher->primitive->szBlock - ecb(mode->ctx)->available;
        in += cipher->primitive->szBlock - ecb(mode->ctx)->available;
        ecb(mode->ctx)->available = 0;
    }

    /* Add whatever is left in the temporary buffer. */
    memcpy(ecb(mode->ctx)->block + ecb(mode->ctx)->available, in, inlen);
    ecb(mode->ctx)->available += inlen;
}

/*! Decrypts a buffer in ECB mode. The context must have been allocated and initialized.
  \param context The initialized encryption context.
  \param in A pointer to the ciphertext buffer.
  \param inlen The size of the ciphertext buffer, in bytes.
  \param out A pointer to the plaintext buffer.
  \param outlen A pointer to an integer which will contain the amount of plaintext output, in bytes.
  \remark The out buffer must have enough space to accomodate up to one more block size of plaintext than ciphertext, rounded down to the nearest block. */
void ECB_DecryptUpdate(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
{
    /* Initialize output size. */
    *outlen = 0;

    /* Process all full blocks except the last potential block (if padding is disabled, also process the last block). */
    while (ecb(mode->ctx)->available + inlen > cipher->primitive->szBlock - (1 - mode->padding))
    {
        /* Copy it in, and process it. */
        memcpy(ecb(mode->ctx)->block + ecb(mode->ctx)->available, in, cipher->primitive->szBlock - ecb(mode->ctx)->available);

        /* Decrypt the block. */
        cipher->primitive->fInverse(cipher, ecb(mode->ctx)->block);

        /* Write back the block to the output. */
        memcpy(out, ecb(mode->ctx)->block, cipher->primitive->szBlock);
        *outlen += cipher->primitive->szBlock;
        out += cipher->primitive->szBlock;

        /* Go forward in the input buffer. */
        inlen -= cipher->primitive->szBlock - ecb(mode->ctx)->available;
        in += cipher->primitive->szBlock - ecb(mode->ctx)->available;
        ecb(mode->ctx)->available = 0;
    }

    /* Save the final block. */
    memcpy(ecb(mode->ctx)->block + ecb(mode->ctx)->available, in, inlen);
    ecb(mode->ctx)->available += inlen;
}

/*! Finalizes an encryption context in ECB mode. The context must have been allocated and initialized.
  \param context The initialized encryption context.
  \param out A pointer to the final plaintext/ciphertext buffer.
  \param outlen A pointer to an integer which will contain the amount of plaintext output, in bytes.
  \return Returns true on success, false on failure.
  \remark The out buffer must have enough space to accomodate up to one block size of plaintext for padding. */
int ECB_EncryptFinal(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* out, size_t* outlen)
{
    unsigned char padding;

    /* If padding is disabled, we need to handle things differently. */
    if (mode->padding == 0)
    {
        /* If there is data left, return an error. */
        if (ecb(mode->ctx)->available != 0) return ORDO_LEFTOVER;

        /* Otherwise, just set the output size to zero. */
        if (outlen != 0) *outlen = 0;
    }
    else
    {
        /* Compute the amount of padding required. */
        padding = cipher->primitive->szBlock - ecb(mode->ctx)->available % cipher->primitive->szBlock;

        /* Write padding to the last block. */
        memset(ecb(mode->ctx)->block + ecb(mode->ctx)->available, padding, padding);

        /* Encrypt the last block. */
        cipher->primitive->fForward(cipher, ecb(mode->ctx)->block);

        /* Write it out to the buffer. */
        memcpy(out, ecb(mode->ctx)->block, cipher->primitive->szBlock);
        *outlen = cipher->primitive->szBlock;
    }

    /* Return success. */
    return ORDO_ESUCCESS;
}

int ECB_DecryptFinal(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* out, size_t* outlen)
{
    unsigned char padding;

    /* If padding is disabled, we need to handle things differently. */
    if (!mode->padding)
    {
        /* If there is data left, return an error. */
        if (ecb(mode->ctx)->available != 0) return ORDO_LEFTOVER;

        /* Otherwise, just set the output size to zero. */
        if (outlen != 0) *outlen = 0;
    }
    else
    {
        /* Otherwise, decrypt the last block. */
        cipher->primitive->fInverse(cipher, ecb(mode->ctx)->block);

        /* Read the amount of padding. */
        padding = *(ecb(mode->ctx)->block + cipher->primitive->szBlock - 1);

        /* Check the padding. */
        if ((padding != 0) && (padding <= cipher->primitive->szBlock) && (padCheck(ecb(mode->ctx)->block + cipher->primitive->szBlock - padding, padding)))
        {
            /* Remove the padding data and output the plaintext. */
            *outlen = cipher->primitive->szBlock - padding;
            memcpy(out, ecb(mode->ctx)->block, *outlen);
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

void ECB_Free(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher)
{
    /* Dellocate context fields. */
    sfree(ecb(mode->ctx)->block, cipher->primitive->szBlock);
    sfree(mode->ctx, sizeof(ECB_ENCRYPT_CONTEXT));
}

/* Fills a ENCRYPT_MODE struct with the correct information. */
void ECB_SetMode(ENCRYPT_MODE* mode)
{
    ENCRYPT_MAKEMODE(mode, ECB_Create, ECB_Init, ECB_EncryptUpdate, ECB_DecryptUpdate, ECB_EncryptFinal, ECB_DecryptFinal, ECB_Free, "ECB");
}
