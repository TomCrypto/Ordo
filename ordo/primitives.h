/**
 * @file primitives.h
 * Exposes the Ordo primitive interface.
 *
 * Header usage mode: External.
 *
 * @see primitives.c
 */

#ifndef primitives_h
#define primitives_h

#include "ordotypes.h"

/* Useful macro to initialize a cipher primitive */
#define PRIMITIVE_MAKECIPHER(p, k, b, t, c, s, f, i, n) p->szKey = k; p->szBlock = b; p->szTweak = t; p->fKeyCheck = c; p->fKeySchedule = (CIPHER_KEYSCHEDULE)s; p->fForward = (CIPHER_PERMUTATION)f; p->fInverse = (CIPHER_PERMUTATION)i; p->name = n;

/*  primitive->szKey = RC4_KEY;
	primitive->szBlock = RC4_BLOCK;
	primitive->szTweak = RC4_TWEAK;
	primitive->fKeyCheck = &RC4_KeyCheck;
	primitive->fKeySchedule = (CIPHER_KEYSCHEDULE)&RC4_KeySchedule;
	primitive->fForward = (CIPHER_PERMUTATION)&RC4_Forward;
	primitive->fInverse = 0;
	primitive->name = "RC4"; */

/*! Prototype for key size checking, which returns true if the passed key size is acceptable, and false otherwise. */
typedef int (*CIPHER_KEYCHECK)(size_t);

/*! Prototype for a primitive key schedule function, taking as an input a key, key size, a tweak and writes the prepared key in the last argument. */
typedef void (* CIPHER_KEYSCHEDULE)(void*, size_t, void*, void*);

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
	CIPHER_KEYCHECK fKeyCheck;
	/*! Points to the primitive's forward permutation function. */
	CIPHER_PERMUTATION fForward;
	/*! Points to the primitive's inverse permutation function. */
	CIPHER_PERMUTATION fInverse;
	/*! Points to the primitive's key schedule. */
	CIPHER_KEYSCHEDULE fKeySchedule;
	/*! The primitive's name. */
	char* name;
} CIPHER_PRIMITIVE;

/*! Loads all primitives. */
void loadPrimitives();

/*! Unloads all primitives. */
void unloadPrimitives();

/*! The NullCipher primitive. */
CIPHER_PRIMITIVE* NullCipher;
/*! The Threefish-256 primitive. */
CIPHER_PRIMITIVE* Threefish256;
/*! The RC4 primitive. */
CIPHER_PRIMITIVE* RC4;

#endif
