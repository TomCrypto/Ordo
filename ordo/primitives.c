#include "primitives.h"

/* Primitive list. */
#include "identity.h"
#include "xortoy.h"
#include "threefish256.h"
#include "rc4.h"

/* Loads all primitives. */
void loadPrimitives()
{
	/* Cipher primitives. */
	Identity_SetPrimitive(&IDENTITY);
	XORToy_SetPrimitive(&XORTOY);
	Threefish256_SetPrimitive(&THREEFISH256);
	RC4_SetPrimitive(&RC4);

	/* Hash primitives. */
	// empty :[
}

/* Unloads all primitives. */
void unloadPrimitives()
{
	free(IDENTITY);
	free(XORTOY);
	free(THREEFISH256);
	free(RC4);
}