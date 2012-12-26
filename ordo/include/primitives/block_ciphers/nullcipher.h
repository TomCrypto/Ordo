#ifndef NULLCIPHER_H
#define NULLCIPHER_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file nullcipher.h
 *
 * \brief NullCipher block cipher.
 *
 * This cipher is compatible with all encryption modes of operation and is only used to debug the library.
 * It accepts no parameters, and has an arbitrarily-chosen 128-bit block size.
 * It accepts any key size but does not even attempt to read the key.
 *
 * @see nullcipher.c
 */

#include <primitives/primitives.h>

BLOCK_CIPHER_CONTEXT* NullCipher_Create();

int NullCipher_Init(BLOCK_CIPHER_CONTEXT* ctx, void* key, size_t keySize, void* params);

void NullCipher_Forward(BLOCK_CIPHER_CONTEXT* ctx, void* block);

void NullCipher_Inverse(BLOCK_CIPHER_CONTEXT* ctx, void* block);

void NullCipher_Free(BLOCK_CIPHER_CONTEXT* ctx);

void NullCipher_SetPrimitive(BLOCK_CIPHER* cipher);

#ifdef __cplusplus
}
#endif

#endif
