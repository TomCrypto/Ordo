#ifndef nullcipher_h
#define nullcipher_h

/**
 * @file nullcipher.h
 *
 * \brief NullCipher cipher interface.
 *
 * This cipher is compatible with all encryption modes of operation and is only used to debug the library.
 * It accepts no parameters, and has an arbitrarily-chosen 128-bit block size.
 * It accepts any key size but does not even attempt to read the key.
 *
 * While being a block cipher, this cipher primitive is actually compatible with the STREAM encryption
 * mode of operation, but this is coincidental and should not be done by definition.
 *
 * @see nullcipher.c
 */

#include <primitives/primitives.h>

BLOCK_CIPHER_CONTEXT* NullCipher_Create(BLOCK_CIPHER* cipher);

int NullCipher_Init(BLOCK_CIPHER_CONTEXT* ctx, void* key, size_t keySize, void* params);

void NullCipher_Forward(BLOCK_CIPHER_CONTEXT* ctx, void* block);

void NullCipher_Inverse(BLOCK_CIPHER_CONTEXT* ctx, void* block);

void NullCipher_Free(BLOCK_CIPHER_CONTEXT* ctx);

void NullCipher_SetPrimitive(BLOCK_CIPHER* cipher);

#endif
