#ifndef stream_h
#define stream_h

/**
 * @file stream.h
 *
 * \brief STREAM encryption mode of operation interface.
 *
 * The STREAM mode is different in that it is only compatible with stream cipher primitives. It is very straightforward
 * and simply gets the stream cipher to generate a keystream which is then combined with the plaintext to produce the
 * ciphertext and vice versa.
 *
 * An important point to note is that this mode ignores the initialization vector completely, as there is no standard
 * way of adding an initialization vector to a stream cipher. To do this, you must use custom constructs to integrate
 * the initialization vector into the encryption key somehow, within the primitive interface.
 *
 * @see stream.c
 */

#include <encrypt/encrypt.h>

void STREAM_Create(ENCRYPT_MODE_CONTEXT*  mode, CIPHER_PRIMITIVE_CONTEXT* cipher);

int STREAM_Init(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, void* iv, void* params);

void STREAM_Update(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen);

int STREAM_Final(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* out, size_t* outlen);

void STREAM_Free(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher);

void STREAM_SetMode(ENCRYPT_MODE* mode);

#endif
