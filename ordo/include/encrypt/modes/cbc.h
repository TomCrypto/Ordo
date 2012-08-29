#ifndef cbc_h
#define cbc_h

/**
 * @file cbc.h
 *
 * \brief CBC encryption mode of operation interface.
 *
 * Contains the CBC encryption mode interface.
 *
 * The CBC mode divides the input message into blocks of the cipher's block size, and encrypts them in a sequential
 * fashion, where each block depends on the previous one (and the first block depends on the initialization vector).
 * If the input message's length is not a multiple of the cipher's block size, a padding mechanism is enabled by
 * default which will pad the message to the correct length (and remove the extra data upon decryption). If
 * padding is explicitly disabled through the mode of operation's parameters, the input's length must be a multiple
 * of the cipher's block size.
 *
 * The padding algorithm is PKCS7 (RFC 5652), which appends N bytes of value N, where N is the number of padding
 * bytes required (between 1 and the cipher's block size in bytes).
 *
 * @see cbc.c
 */

#include <encrypt/encrypt.h>

/*! A parameter structure for CBC mode - this only contains whether padding should be enabled. */
typedef struct CBC_PARAMS
{
    /*! Set to 0 to disable padding, 1 to enable it. */
    size_t padding;
} CBC_PARAMS;

void CBC_Create(ENCRYPT_MODE_CONTEXT*  mode, CIPHER_PRIMITIVE_CONTEXT* cipher);

int CBC_Init(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, void* iv, CBC_PARAMS* params);

void CBC_Update(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen);

int CBC_Final(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* out, size_t* outlen);

void CBC_Free(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher);

void CBC_SetMode(ENCRYPT_MODE* mode);

#endif
