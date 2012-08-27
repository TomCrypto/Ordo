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
#define PRIMITIVE_MAKECIPHER(p, b, c, i, pf, pi, f, n) p->szBlock = b; p->fCreate = c; p->fInit = (CIPHER_INIT)i; p->fForward = (CIPHER_UPDATE)pf; p->fInverse = (CIPHER_UPDATE)pi; p->fFree = f; p->name = n;

/*! Reads the name of a primitive. */
#define primitiveName(p) (p->name)
/*! Reads the block size of a primitive. */
#define primitiveBlockSize(p) (p->szBlock)

/*! Represents a cipher primitive context. */
typedef struct CIPHER_PRIMITIVE_CONTEXT
{
    /*! The cipher primitive in use. */
    struct CIPHER_PRIMITIVE* primitive;
    /*! The cipher primitive context. */
    void* cipher;
} CIPHER_PRIMITIVE_CONTEXT;

/*! Prototype for allocating and freeing cipher primitive contexts. */
typedef void (*CIPHER_ALLOC)(CIPHER_PRIMITIVE_CONTEXT*);

/*! Prototype for initializing a cipher primitive context. */
typedef int (*CIPHER_INIT)(CIPHER_PRIMITIVE_CONTEXT*, void*, size_t, void*);

/*! Prototype for cipher primitive context forward and inverse updates. */
typedef void (*CIPHER_UPDATE)(CIPHER_PRIMITIVE_CONTEXT*, void*, size_t);

/*! This structure defines a symmetric cipher primitive. */
typedef struct CIPHER_PRIMITIVE
{
    /*! The block size, in bytes. */
    size_t szBlock;

    CIPHER_ALLOC fCreate;
    CIPHER_INIT fInit;
    CIPHER_UPDATE fForward;
    CIPHER_UPDATE fInverse;
    CIPHER_ALLOC fFree;

    /*! The primitive's name. */
    char* name;
} CIPHER_PRIMITIVE;

/*! Loads all primitives. */
void loadPrimitives();

/*! Unloads all primitives. */
void unloadPrimitives();

/*! The NullCipher primitive. */
CIPHER_PRIMITIVE* NullCipher;

/*! The RC4 primitive. */
CIPHER_PRIMITIVE* RC4;

/*! The RC5-64/16 primitive. */
CIPHER_PRIMITIVE* RC5_64_16;

#endif
