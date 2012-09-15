#ifndef ctr_h
#define ctr_h

/**
 * @file ctr.h
 *
 * \brief CTR encryption mode of operation interface.
 *
 * The CTR mode generates a keystream by repeatedly encrypting a counter starting from some
 * initialization vector, effectively turning a block cipher into a stream cipher. As such,
 * CTR mode requires no padding, and outlen will always be equal to inlen.
 *
 * Note that the CTR keystream is independent of the plaintext, and is also spatially coherent
 * (using a given initialization vector on a len-byte message will "use up" len bytes of the
 * keystream) so care must be taken to avoid reusing the initialization vector in an insecure
 * way. This also means the block cipher's inverse permutation is never used.
 *
 * \c CTR_Final accepts 0 as an argument for \c outlen, since by design the CTR mode of operation does not
 * produce any final data. However, if a valid pointer is passed, its value will be set to zero as expected.
 *
 * @see ctr.c
 */

#include <encrypt/encrypt.h>

ENCRYPT_MODE_CONTEXT* CTR_Create(ENCRYPT_MODE* mode, CIPHER_PRIMITIVE_CONTEXT* cipher);

int CTR_Init(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, void* iv, void* params);

void CTR_Update(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen);

int CTR_Final(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* out, size_t* outlen);

void CTR_Free(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher);

void CTR_SetMode(ENCRYPT_MODE* mode);

#endif
