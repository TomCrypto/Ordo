#ifndef ecb_h
#define ecb_h

/**
 * @file ecb.h
 *
 * \brief ECB encryption mode of operation interface.
 *
 * Contains the ECB encryption mode interface.
 *
 * The ECB mode divides the input message into blocks of the cipher's block size, and encrypts them individually.
 * If the input message's length is not a multiple of the cipher's block size, a padding mechanism is enabled by
 * default which will pad the message to the correct length (and remove the extra data upon decryption). If
 * padding is explicitly disabled through the mode of operation's parameters, the input's length must be a multiple
 * of the cipher's block size.
 *
 * The padding algorithm is PKCS7 (RFC 5652), which appends N bytes of value N, where N is the number of padding
 * bytes required (between 1 and the cipher's block size in bytes).
 *
 * The ECB mode does not require an initialization vector.
 *
 * Note that the ECB mode is insecure in almost all situations and is not recommended for use.
 *
 * @see ecb.c
 */

#include <encrypt/encrypt.h>

/*! A parameter structure for ECB mode - this only contains whether padding should be enabled. */
typedef struct ECB_PARAMS
{
    /*! Set to 0 to disable padding, 1 to enable it. */
    size_t padding;
} ECB_PARAMS;

void ECB_Create(ENCRYPT_MODE_CONTEXT*  mode, CIPHER_PRIMITIVE_CONTEXT* cipher);

int ECB_Init(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, void* iv, ECB_PARAMS* params);

void ECB_Update(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen);

int ECB_Final(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* out, size_t* outlen);

void ECB_Free(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher);

void ECB_SetMode(ENCRYPT_MODE* mode);

#endif
