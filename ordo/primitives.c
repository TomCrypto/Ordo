#include "primitives.h"

/* Primitive list. */
#include "nullcipher.h"
#include "threefish256.h"
#include "rc4.h"

/* Loads all primitives. */
void loadPrimitives()
{
	/* Cipher primitives. */
	NullCipher_SetPrimitive(&NullCipher);
	Threefish256_SetPrimitive(&THREEFISH256);
	RC4_SetPrimitive(&RC4);

	/* Hash primitives. */
	// empty :[
}

/* Unloads all primitives. */
void unloadPrimitives()
{
	free(NullCipher);
	free(THREEFISH256);
	free(RC4);
}
