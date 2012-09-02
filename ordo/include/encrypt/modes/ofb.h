#ifndef ofb_h
#define ofb_h

/**
 * @file ofb.h
 *
 * \brief OFB encryption mode of operation interface.
 *
 * The OFB mode generates a keystream by repeatedly encrypting an initialization vector, effectively
 * turning a block cipher into a stream cipher. As such, OFB mode requires no padding, and outlen
 * will always be equal to inlen.
 *
 * Note that the OFB keystream is independent of the plaintext, so a key/iv pair must never be
 * used for more than one message. This also means the block cipher's inverse permutation is
 * never used.
 *
 * @see ofb.c
 */

#include <encrypt/encrypt.h>

void OFB_Create(ENCRYPT_MODE_CONTEXT*  mode, CIPHER_PRIMITIVE_CONTEXT* cipher);

int OFB_Init(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, void* iv, void* params);

void OFB_Update(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen);

int OFB_Final(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* out, size_t* outlen);

void OFB_Free(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher);

void OFB_SetMode(ENCRYPT_MODE* mode);

#endif
