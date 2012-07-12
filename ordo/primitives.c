#include "primitives.h"

/* Primitive list. */
#include "identity.h"
#include "xortoy.h"
#include "threefish256.h"

/* Loads all primitives. */
void loadPrimitives()
{
	/* Cipher primitives. */
	Identity_SetPrimitive(&IDENTITY);
	XORToy_SetPrimitive(&XORTOY);
	Threefish256_SetPrimitive(&THREEFISH256);

	/* Hash primitives. */
	// empty :[
}

/* Unloads all primitives. */
void unloadPrimitives()
{
	free(IDENTITY);
	free(XORTOY);
	free(THREEFISH256);
}