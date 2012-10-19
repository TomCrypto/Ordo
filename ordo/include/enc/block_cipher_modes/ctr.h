#ifndef CTR_H
#define CTR_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file ctr.h
 *
 * \brief CTR block cipher mode of operation.
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
 * \c CTR_Final() accepts 0 as an argument for \c outlen, since by design the CTR mode of operation does not
 * produce any final data. However, if a valid pointer is passed, its value will be set to zero as expected.
 *
 * @see ctr.c
 */

#include <enc/enc_block.h>

BLOCK_CIPHER_MODE_CONTEXT* CTR_Create(BLOCK_CIPHER_CONTEXT* cipherCtx);

int CTR_Init(BLOCK_CIPHER_MODE_CONTEXT* mode, BLOCK_CIPHER_CONTEXT* cipherCtx, void* iv, void* params);

void CTR_Update(BLOCK_CIPHER_MODE_CONTEXT* mode, BLOCK_CIPHER_CONTEXT* cipherCtx,
                unsigned char* in, size_t inlen,
                unsigned char* out, size_t* outlen);

int CTR_Final(BLOCK_CIPHER_MODE_CONTEXT* mode, BLOCK_CIPHER_CONTEXT* cipherCtx, unsigned char* out, size_t* outlen);

void CTR_Free(BLOCK_CIPHER_MODE_CONTEXT* mode, BLOCK_CIPHER_CONTEXT* cipherCtx);

void CTR_SetMode(BLOCK_CIPHER_MODE* mode);

#ifdef __cplusplus
}
#endif

#endif
