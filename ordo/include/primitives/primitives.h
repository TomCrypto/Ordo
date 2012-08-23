#ifndef primitives_h
#define primitives_h

/**
 * @file primitives.h
 * Exposes the Ordo primitive interface.
 *
 * Header usage mode: External.
 *
 * @see primitives.c
 */

#include <common/ordotypes.h>

/* Useful macro to initialize a cipher primitive */
#define PRIMITIVE_MAKECIPHER(p, k, b, t, c, s, f, i, n) p->szKey = k; p->szBlock = b; p->szTweak = t; p->fKeyCheck = c; p->fKeySchedule = (CIPHER_KEYSCHEDULE)s; p->fForward = (CIPHER_PERMUTATION)f; p->fInverse = (CIPHER_PERMUTATION)i; p->name = n;

/*! Reads the name of a primitive. */
#define primitiveName(p) (p->name)
/*! Reads the block size of a primitive. */
#define primitiveBlockSize(p) (p->szBlock)
/*! Reads the tweak size of a primitive. */
#define primitiveTweakSize(p) (p->szTweak)

/*! Prototype for key size checking, which returns true if the passed key size is acceptable, and false otherwise. */
typedef int (*CIPHER_KEYCHECK)(size_t);

/*! Prototype for a primitive key schedule function, taking as an input a key, key size, a tweak and writes the prepared key in the last argument. */
typedef void (* CIPHER_KEYSCHEDULE)(void*, size_t, void*, void*, void*);

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
/*! The RC5-64/16 primitive. */
CIPHER_PRIMITIVE* RC5_64_16;

#endif
