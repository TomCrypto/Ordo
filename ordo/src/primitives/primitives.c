#include <primitives/primitives.h>

/* Primitive list. */
#include <primitives/ciphers/nullcipher.h>
#include <primitives/ciphers/rc4.h>
#include <primitives/ciphers/rc5_64_16.h>

/* Loads all primitives. */
void loadPrimitives()
{
    /* Cipher primitives. */
    NullCipher = malloc(sizeof(CIPHER_PRIMITIVE));
    NullCipher_SetPrimitive(NullCipher);

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
    free(RC4);
}
