#ifndef cbc_h
#define cbc_h

/**
 * @file cbc.h
 *
 * \brief CBC encryption mode of operation interface.
 *
 * The CBC mode divides the input message into blocks of the cipher's block size, and encrypts them in a sequential
 * fashion, where each block depends on the previous one (and the first block depends on the initialization vector).
 * If the input message's length is not a multiple of the cipher's block size, a padding mechanism is enabled by
 * default which will pad the message to the correct length (and remove the extra data upon decryption). If
 * padding is explicitly disabled through the mode of operation's parameters, the input's length must be a multiple
 * of the cipher's block size.
 *
 * If padding is enabled, \c CBC_Final requires a valid pointer to be passed in the \c outlen parameter and will always
 * return a full blocksize of data, containing the last few ciphertext bytes containing the padding information.
 *
 * If padding is disabled, \c outlen is also required, and will return the number of unprocessed plaintext bytes in the
 * context. If this is any value other than zero, the function will also fail with \c ORDO_ELEFTOVER.
 *
 * @see cbc.c
 */

#include <encrypt/encrypt.h>

/*! \brief CBC mode of operation parameters.
 *
 * A parameter structure for CBC mode - this only contains whether padding should be enabled. */
typedef struct CBC_PARAMS
{
    /*! Set the least significant bit to 0 to disable padding, 1 to enable it. All other bits are ignored. Enabled by default. */
    size_t padding;
} CBC_PARAMS;

ENCRYPT_MODE_CONTEXT* CBC_Create(ENCRYPT_MODE* mode, CIPHER_PRIMITIVE_CONTEXT* cipher);

int CBC_Init(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, void* iv, CBC_PARAMS* params);

void CBC_Update(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen);

int CBC_Final(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* out, size_t* outlen);

void CBC_Free(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher);

void CBC_SetMode(ENCRYPT_MODE* mode);

#endif
