#include <primitives/primitives.h>

/* Primitive list. */
#include <primitives/ciphers/nullcipher.h>
#include <primitives/ciphers/threefish256.h>
#include <primitives/ciphers/rc4.h>

/* Cipher primitive list. */
CIPHER_PRIMITIVE* _NullCipher;
CIPHER_PRIMITIVE* _RC4;
CIPHER_PRIMITIVE* _Threefish256;

/* Loads all primitives. */
void loadPrimitives()
{
    /* Cipher primitives. */
    _NullCipher = malloc(sizeof(CIPHER_PRIMITIVE));
    NullCipher_SetPrimitive(_NullCipher);

    _Threefish256 = malloc(sizeof(CIPHER_PRIMITIVE));
    Threefish256_SetPrimitive(_Threefish256);

    _RC4 = malloc(sizeof(CIPHER_PRIMITIVE));
    RC4_SetPrimitive(_RC4);

    /* Hash primitives. */
    /* empty :[ */
}

/* Unloads all primitives. */
void unloadPrimitives()
{
    free(_NullCipher);
    free(_Threefish256);
    free(_RC4);
}

/* Pass-through functions to acquire primitives. */
CIPHER_PRIMITIVE* NullCipher() { return _NullCipher; }
CIPHER_PRIMITIVE* RC4() { return _RC4; }
CIPHER_PRIMITIVE* Threefish256() { return _Threefish256; }
