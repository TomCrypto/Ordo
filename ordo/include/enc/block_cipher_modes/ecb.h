#ifndef ECB_H
#define ECB_H

/**
 * @file ecb.h
 *
 * \brief ECB block cipher mode of operation.
 *
 * The ECB mode divides the input message into blocks of the cipher's block size, and encrypts them individually.
 * If the input message's length is not a multiple of the cipher's block size, a padding mechanism is enabled by
 * default which will pad the message to the correct length (and remove the extra data upon decryption). If
 * padding is explicitly disabled through the mode of operation's parameters, the input's length must be a multiple
 * of the cipher's block size.
 *
 * If padding is enabled, \c ECB_Final() requires a valid pointer to be passed in the \c outlen parameter and will
 * always return a full blocksize of data, containing the last few ciphertext bytes containing the padding information.
 *
 * If padding is disabled, \c outlen is also required, and will return the number of unprocessed plaintext bytes in the
 * context. If this is any value other than zero, the function will also fail with \c ORDO_ELEFTOVER.
 *
 *
 * The ECB mode does not require an initialization vector.
 *
 * Note that the ECB mode is insecure in almost all situations and is not recommended for use.
 *
 * @see ecb.c
 */

#include <enc/enc_block.h>

/*! \brief ECB mode of operation parameters.
 *
 * A parameter structure for ECB mode - this only contains whether padding should be enabled. */
typedef struct ECB_PARAMS
{
    /*! Set the least significant bit to 0 to disable padding, 1 to enable it. All other bits are ignored. The default
    * behaviour is 1. */
    size_t padding;
} ECB_PARAMS;

BLOCK_CIPHER_MODE_CONTEXT* ECB_Create(BLOCK_CIPHER_CONTEXT* cipherCtx);

int ECB_Init(BLOCK_CIPHER_MODE_CONTEXT* mode, BLOCK_CIPHER_CONTEXT* cipherCtx, void* iv, ECB_PARAMS* params);

void ECB_Update(BLOCK_CIPHER_MODE_CONTEXT* mode, BLOCK_CIPHER_CONTEXT* cipherCtx,
                unsigned char* in, size_t inlen,
                unsigned char* out, size_t* outlen);

int ECB_Final(BLOCK_CIPHER_MODE_CONTEXT* mode, BLOCK_CIPHER_CONTEXT* cipherCtx, unsigned char* out, size_t* outlen);

void ECB_Free(BLOCK_CIPHER_MODE_CONTEXT* mode, BLOCK_CIPHER_CONTEXT* cipherCtx);

void ECB_SetMode(BLOCK_CIPHER_MODE* mode);

#endif
