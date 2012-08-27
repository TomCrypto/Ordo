#include <primitives/primitives.h>

/* Primitive list. */
#include <primitives/ciphers/nullcipher.h>

/* Loads all primitives. */
void loadPrimitives()
{
    /* Cipher primitives. */
    NullCipher = malloc(sizeof(CIPHER_PRIMITIVE));
    NullCipher_SetPrimitive(NullCipher);

    /* Hash primitives. */
    /* empty :[ */
}

/* Unloads all primitives. */
void unloadPrimitives()
{
    free(NullCipher);
}
