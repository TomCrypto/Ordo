/**
 * @file nullcipher.c
 * Implements the NullCipher cipher primitive. This cipher is a test cipher which only exists as a debugging tool, and should not be used in any other context.
 *
 * The cipher itself does nothing and accepts any key size. It has a block size of 128 bits.
 *
 * @see nullcipher.h
 */

#include <primitives/primitives.h>
#include <primitives/ciphers/nullcipher.h>

#define NULLCIPHER_BLOCK (16)

void NullCipher_Create(CIPHER_PRIMITIVE_CONTEXT* cipher)
{
    /* Nothing happens here, as the NullCipher maintains no state. */
}

int NullCipher_Init(CIPHER_PRIMITIVE_CONTEXT* cipher, void* key, size_t keySize, void* params)
{
    /* Ignore everything! */
    return ORDO_ESUCCESS;
}

void NullCipher_Forward(CIPHER_PRIMITIVE_CONTEXT* cipher, void* block, size_t len)
{
    /* Identity permutation... do nothing. */
}

void NullCipher_Inverse(CIPHER_PRIMITIVE_CONTEXT* cipher, void* block, size_t len)
{
    /* Idem! */
}

void NullCipher_Free(CIPHER_PRIMITIVE_CONTEXT* cipher)
{
    /* Nothing to free... */
}

/* Fills a CIPHER_PRIMITIVE struct with the correct information. */
void NullCipher_SetPrimitive(CIPHER_PRIMITIVE* primitive)
{
    PRIMITIVE_MAKECIPHER(primitive, NULLCIPHER_BLOCK, NullCipher_Create, NullCipher_Init, NullCipher_Forward, NullCipher_Inverse, NullCipher_Free, "NullCipher");
}
