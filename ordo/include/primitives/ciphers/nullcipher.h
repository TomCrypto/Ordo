#ifndef nullcipher_h
#define nullcipher_h

/**
 * @file nullcipher.h
 *
 * \brief NullCipher cipher interface.
 *
 * Contains the NullCipher cipher primitive interface. This cipher is compatible with all encryption modes of operation
 * and is only used to debug the library. It accepts no parameters, and has an arbitrarily-chosen 128-bit block size.
 * It accepts any key size but does not even attempt to read the key.
 *
 * @see nullcipher.c
 */

#include <primitives/primitives.h>

/*! This does nothing as the NullCipher maintains no context, and can safely be ignored. */
void NullCipher_Create(CIPHER_PRIMITIVE_CONTEXT* cipher);

/*! This does nothing. All parameters are left unread. */
int NullCipher_Init(CIPHER_PRIMITIVE_CONTEXT* cipher, void* key, size_t keySize, void* params);

/*! This function does nothing. */
void NullCipher_Forward(CIPHER_PRIMITIVE_CONTEXT* cipher, void* block, size_t len);

/*! This function does nothing. */
void NullCipher_Inverse(CIPHER_PRIMITIVE_CONTEXT* cipher, void* block, size_t len);

/*! This function does nothing. */
void NullCipher_Free(CIPHER_PRIMITIVE_CONTEXT* cipher);

/*! This function will populate a cipher primitive object with the NullCipher details. */
void NullCipher_SetPrimitive(CIPHER_PRIMITIVE* primitive);

#endif
