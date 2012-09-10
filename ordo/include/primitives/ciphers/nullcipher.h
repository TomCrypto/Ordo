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

CIPHER_PRIMITIVE_CONTEXT* NullCipher_Create(CIPHER_PRIMITIVE* primitive);

int NullCipher_Init(CIPHER_PRIMITIVE_CONTEXT* cipher, void* key, size_t keySize, void* params);

void NullCipher_Forward(CIPHER_PRIMITIVE_CONTEXT* cipher, void* block, size_t len);

void NullCipher_Inverse(CIPHER_PRIMITIVE_CONTEXT* cipher, void* block, size_t len);

void NullCipher_Free(CIPHER_PRIMITIVE_CONTEXT* cipher);

void NullCipher_SetPrimitive(CIPHER_PRIMITIVE* primitive);

#endif
