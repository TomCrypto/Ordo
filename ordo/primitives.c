#include "primitives.h"

/* Primitive list. */
#include "nullcipher.h"
#include "threefish256.h"
#include "rc4.h"

/* Loads all primitives. */
void loadPrimitives()
{
	/* Cipher primitives. */
	NullCipher = malloc(sizeof(CIPHER_PRIMITIVE)); NullCipher_SetPrimitive(NullCipher);
	Threefish256 = malloc(sizeof(CIPHER_PRIMITIVE)); Threefish256_SetPrimitive(Threefish256);
	RC4 = malloc(sizeof(CIPHER_PRIMITIVE)); RC4_SetPrimitive(RC4);

	/* Hash primitives. */
	/* empty :[ */
}

/* Unloads all primitives. */
void unloadPrimitives()
{
	free(NullCipher);
	free(Threefish256);
	free(RC4);
}
