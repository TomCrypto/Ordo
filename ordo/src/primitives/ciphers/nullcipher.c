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

#define NULLCIPHER_KEY (0)
#define NULLCIPHER_BLOCK (16)
#define NULLCIPHER_TWEAK (0)

int NullCipher_KeyCheck(size_t keySize)
{
    /* All key sizes are permitted for this cipher. */
    return 1;
}

/* NullCipher key schedule. */
void NullCipher_KeySchedule(void* rawKey, size_t len, void* tweak, void* key)
{
    return;
}

/* NullCipher forward permutation function. */
void NullCipher_Forward(void* block, void* key)
{
    return;
}

/* NullCipher inverse permutation function. */
void NullCipher_Inverse(void* block, void* key)
{
    return;
}

/* Fills a CIPHER_PRIMITIVE struct with the correct information. */
void NullCipher_SetPrimitive(CIPHER_PRIMITIVE* primitive)
{
    PRIMITIVE_MAKECIPHER(primitive, NULLCIPHER_KEY, NULLCIPHER_BLOCK, NULLCIPHER_TWEAK, NullCipher_KeyCheck, NullCipher_KeySchedule, NullCipher_Forward, NullCipher_Inverse, "NullCipher");
}
