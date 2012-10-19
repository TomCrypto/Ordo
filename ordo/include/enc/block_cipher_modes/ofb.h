#ifndef OFB_H
#define OFB_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file ofb.h
 *
 * \brief OFB block cipher mode of operation.
 *
 * The OFB mode generates a keystream by repeatedly encrypting an initialization vector, effectively
 * turning a block cipher into a stream cipher. As such, OFB mode requires no padding, and outlen
 * will always be equal to inlen.
 *
 * Note that the OFB keystream is independent of the plaintext, so a key/iv pair must never be
 * used for more than one message. This also means the block cipher's inverse permutation is
 * never used.
 *
 * \c OFB_Final() accepts 0 as an argument for \c outlen, since by design the OFB mode of operation does not
 * produce any final data. However, if a valid pointer is passed, its value will be set to zero as expected.
 *
 * @see ofb.c
 */

#include <enc/enc_block.h>

BLOCK_CIPHER_MODE_CONTEXT* OFB_Create(BLOCK_CIPHER_CONTEXT* cipherCtx);

int OFB_Init(BLOCK_CIPHER_MODE_CONTEXT* mode, BLOCK_CIPHER_CONTEXT* cipherCtx, void* iv, void* params);

void OFB_Update(BLOCK_CIPHER_MODE_CONTEXT* mode, BLOCK_CIPHER_CONTEXT* cipherCtx,
                unsigned char* in, size_t inlen,
                unsigned char* out, size_t* outlen);

int OFB_Final(BLOCK_CIPHER_MODE_CONTEXT* mode, BLOCK_CIPHER_CONTEXT* cipherCtx, unsigned char* out, size_t* outlen);

void OFB_Free(BLOCK_CIPHER_MODE_CONTEXT* mode, BLOCK_CIPHER_CONTEXT* cipherCtx);

void OFB_SetMode(BLOCK_CIPHER_MODE* mode);

#ifdef __cplusplus
}
#endif

#endif
