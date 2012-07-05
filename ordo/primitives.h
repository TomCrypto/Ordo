/*! \file */

#ifndef primitives_h
#define primitives_h

#include "ordotypes.h" 

/*! Prototype for key size checking, which returns true if the passed key size is acceptable, and false otherwise. */
typedef bool (*CIPHER_KEYSIZECHECK)(size_t);

/*! Prototype for a primitive key schedule function, taking as an input a key, key size, a tweak and writes the prepared key in the last argument. */
typedef bool (* CIPHER_KEYSCHEDULE)(void*, size_t, void*, void*);

/*! Prototype for a primitive's permutation function, taking as an input a block and key. */
typedef void (* CIPHER_PERMUTATION)(void*, void*);

/*! This structure defines a symmetric cipher primitive. */
typedef struct CIPHER_PRIMITIVE
{
	/*! The key size, in bytes, this includes all key material such as key-derived substitution boxes. */
	size_t szKey;
	/*! The block size, in bytes. */
	size_t szBlock;
	/*! The tweak size, in bytes. */
	size_t szTweak;
	/*! Points to the key size verification function. */
	CIPHER_KEYSIZECHECK fKeySizeCheck;
	/*! Points to the primitive's permutation function. */
	CIPHER_PERMUTATION fPermutation;
	/*! Points to the primitive's inverse permutation function. */
	CIPHER_PERMUTATION fInverse;
	/*! Points to the primitive's key schedule. */
	CIPHER_KEYSCHEDULE fKeySchedule;
	/*! The primitive's name. */
	char* name;
} CIPHER_PRIMITIVE;

/*! Initializes all primitives. */
void loadPrimitives();

/*! The Identity primitive. */
CIPHER_PRIMITIVE* IDENTITY;
/*! The XORToy primitive. */
CIPHER_PRIMITIVE* XORTOY;
/*! The Threefish-256 primitive. */
CIPHER_PRIMITIVE* THREEFISH256;

#endif