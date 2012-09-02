#ifndef primitives_h
#define primitives_h

/**
 * @file primitives.h
 *
 * \brief Cryptographic primitive interface.
 *
 * Exposes the Ordo primitive interface, which abstracts various cryptographic primitives through high-level interfaces.
 * Note it is always possible to skip this API and directly access the lower-level primitive functions, but it is discouraged.
 *
 * @see primitives.c
 */

/* Library dependencies. */
#include <common/ordotypes.h>

/* Useful macro to initialize a cipher primitive. */
#define PRIMITIVE_MAKECIPHER(p, b, c, i, pf, pi, f, n) p->szBlock = b; p->fCreate = c; p->fInit = (CIPHER_INIT)i; p->fForward = (CIPHER_UPDATE)pf; p->fInverse = (CIPHER_UPDATE)pi; p->fFree = f; p->name = n;

/*! Returns the name of a primitive. */
#define primitiveName(p) (p->name)
/*! Returns the block size of a cipher primitive. */
#define cipherPrimitiveBlockSize(p) (p->szBlock)

/*! \brief Cipher primitive context.
 *
 * This structure describes a cipher primitive context. It is used by
 * cipher primitives to maintain their state across function calls (this
 * includes key material and/or actual state for stream ciphers).
 * It should never be modified outside of these functions. */
typedef struct CIPHER_PRIMITIVE_CONTEXT
{
    /*! The cipher primitive in use. */
    struct CIPHER_PRIMITIVE* primitive;
    /*! The low-level cipher primitive context. */
    void* cipher;
} CIPHER_PRIMITIVE_CONTEXT;

/* Prototype for allocating and freeing cipher primitive contexts. */
typedef void (*CIPHER_ALLOC)(CIPHER_PRIMITIVE_CONTEXT*);

/* Prototype for initializing a cipher primitive context. */
typedef int (*CIPHER_INIT)(CIPHER_PRIMITIVE_CONTEXT*, void*, size_t, void*);

/* Prototype for cipher primitive context forward and inverse updates. */
typedef void (*CIPHER_UPDATE)(CIPHER_PRIMITIVE_CONTEXT*, void*, size_t);

/* This structure defines a symmetric cipher primitive. */
typedef struct CIPHER_PRIMITIVE
{
    /* The block size, in bytes, of the cipher primitive. */
    size_t szBlock;
    /* Points to the cipher primitive context creation function. */
    CIPHER_ALLOC fCreate;
    /* Points to the cipher primitive context initialization function. */
    CIPHER_INIT fInit;
    /* Points to the cipher primitive context forward update function. */
    CIPHER_UPDATE fForward;
    /* Points to the cipher primitive context inverse update function. */
    CIPHER_UPDATE fInverse;
    /* Points to the cipher primitive context free function. */
    CIPHER_ALLOC fFree;
    /* The cipher primitive's name. */
    char* name;
} CIPHER_PRIMITIVE;

/*! Loads all primitives. This must be called (or the primitive objects must be initialized by some other means) before
 * the NullCipher, RC4, etc... global variables can be used in any way through this interface. */
void loadPrimitives();

/*! Unloads all primitives. After calling this, the NullCipher, RC4... primitive objects may no longer be used. */
void unloadPrimitives();

/*! The NullCipher cipher primitive. */
CIPHER_PRIMITIVE* NullCipher();

/*! The RC4 cipher primitive. */
CIPHER_PRIMITIVE* RC4();

/*! The Threefish-256 cipher primitive. */
CIPHER_PRIMITIVE* Threefish256();

#endif
