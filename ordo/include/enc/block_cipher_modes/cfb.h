#ifndef cfb_h
#define cfb_h

/**
 * @file cfb.h
 *
 * \brief CFB encryption mode of operation interface.
 *
 * The CFB mode generates a keystream by repeatedly encrypting an initialization vector and mixing in
 * the plaintext, effectively turning a block cipher into a stream cipher. As such, CFB mode requires no
 * padding, and outlen will always be equal to inlen.
 *
 * Note that the CFB keystream depends on the plaintext fed into it, as opposed to OFB mode. This also
 * means the block cipher's inverse permutation is never used.
 *
 * \c CFB_Final accepts 0 as an argument for \c outlen, since by design the CFB mode of operation does not
 * produce any final data. However, if a valid pointer is passed, its value will be set to zero as expected.
 *
 * @see cfb.c
 */

#include <enc/enc_block.h>

BLOCK_CIPHER_MODE_CONTEXT* CFB_Create(BLOCK_CIPHER_MODE* mode, BLOCK_CIPHER_CONTEXT* cipherCtx);

int CFB_Init(BLOCK_CIPHER_MODE_CONTEXT* mode, BLOCK_CIPHER_CONTEXT* cipherCtx, void* iv, void* params);

void CFB_Update(BLOCK_CIPHER_MODE_CONTEXT* mode, BLOCK_CIPHER_CONTEXT* cipherCtx, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen);

int CFB_Final(BLOCK_CIPHER_MODE_CONTEXT* mode, BLOCK_CIPHER_CONTEXT* cipherCtx, unsigned char* out, size_t* outlen);

void CFB_Free(BLOCK_CIPHER_MODE_CONTEXT* mode, BLOCK_CIPHER_CONTEXT* cipherCtx);

void CFB_SetMode(BLOCK_CIPHER_MODE* mode);

#endif
