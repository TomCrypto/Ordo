#ifndef CBC_H
#define CBC_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file cbc.h
 *
 * \brief CBC block cipher mode of operation.
 *
 * The CBC mode divides the input message into blocks of the cipher's block size, and encrypts them in a sequential
 * fashion, where each block depends on the previous one (and the first block depends on the initialization vector).
 * If the input message's length is not a multiple of the cipher's block size, a padding mechanism is enabled by
 * default which will pad the message to the correct length (and remove the extra data upon decryption). If
 * padding is explicitly disabled through the mode of operation's parameters, the input's length must be a multiple
 * of the cipher's block size.
 *
 * If padding is enabled, \c CBC_Final() requires a valid pointer to be passed in the \c outlen parameter and will
 * always return a full blocksize of data, containing the last few ciphertext bytes containing the padding information.
 *
 * If padding is disabled, \c outlen is also required, and will return the number of unprocessed plaintext bytes in the
 * context. If this is any value other than zero, the function will also fail with \c ORDO_ELEFTOVER.
 *
 * @see cbc.c
 */

#include <enc/enc_block.h>

/*! \brief CBC mode of operation parameters.
 *
 * A parameter structure for CBC mode - this only contains whether padding should be enabled. */
typedef struct CBC_PARAMS
{
    /*! Set the least significant bit to 0 to disable padding, 1 to enable it. All other bits are ignored. The default
    * behaviour is 1. */
    size_t padding;
} CBC_PARAMS;

BLOCK_CIPHER_MODE_CONTEXT* CBC_Create(BLOCK_CIPHER_CONTEXT* cipherCtx);

int CBC_Init(BLOCK_CIPHER_MODE_CONTEXT* mode, BLOCK_CIPHER_CONTEXT* cipherCtx, void* iv, CBC_PARAMS* params);

void CBC_Update(BLOCK_CIPHER_MODE_CONTEXT* mode, BLOCK_CIPHER_CONTEXT* cipherCtx,
                unsigned char* in, size_t inlen,
                unsigned char* out, size_t* outlen);

int CBC_Final(BLOCK_CIPHER_MODE_CONTEXT* mode, BLOCK_CIPHER_CONTEXT* cipherCtx, unsigned char* out, size_t* outlen);

void CBC_Free(BLOCK_CIPHER_MODE_CONTEXT* mode, BLOCK_CIPHER_CONTEXT* cipherCtx);

void CBC_SetMode(BLOCK_CIPHER_MODE* mode);

#ifdef __cplusplus
}
#endif

#endif
