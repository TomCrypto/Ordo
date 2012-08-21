#include <primitives/primitives.h>

/* Primitive list. */
#include <primitives/ciphers/nullcipher.h>
#include <primitives/ciphers/threefish256.h>
#include <primitives/ciphers/rc4.h>
#include <primitives/ciphers/rc5_64_16.h>

/* Loads all primitives. */
void loadPrimitives()
{
    /* Cipher primitives. */
    NullCipher = malloc(sizeof(CIPHER_PRIMITIVE));
    NullCipher_SetPrimitive(NullCipher);

    Threefish256 = malloc(sizeof(CIPHER_PRIMITIVE));
    Threefish256_SetPrimitive(Threefish256);

    RC4 = malloc(sizeof(CIPHER_PRIMITIVE));
    RC4_SetPrimitive(RC4);

    RC5_64_16 = malloc(sizeof(CIPHER_PRIMITIVE));
    RC5_64_16_SetPrimitive(RC5_64_16);

    /* Hash primitives. */
    /* empty :[ */
}

/* Unloads all primitives. */
void unloadPrimitives()
{
    free(NullCipher);
    free(Threefish256);
    free(RC4);
    free(RC5_64_16);
}
