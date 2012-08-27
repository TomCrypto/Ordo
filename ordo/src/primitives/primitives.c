#include <primitives/primitives.h>

/* Primitive list. */
#include <primitives/ciphers/nullcipher.h>
#include <primitives/ciphers/rc4.h>

/* Loads all primitives. */
void loadPrimitives()
{
    /* Cipher primitives. */
    NullCipher = malloc(sizeof(CIPHER_PRIMITIVE));
    NullCipher_SetPrimitive(NullCipher);

    RC4 = malloc(sizeof(CIPHER_PRIMITIVE));
    RC4_SetPrimitive(RC4);

    /* Hash primitives. */
    /* empty :[ */
}

/* Unloads all primitives. */
void unloadPrimitives()
{
    free(NullCipher);
    free(RC4);
}
