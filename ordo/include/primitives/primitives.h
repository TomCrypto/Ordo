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
typedef CIPHER_PRIMITIVE_CONTEXT* (*CIPHER_ALLOC)(struct CIPHER_PRIMITIVE*);

/* Prototype for initializing a cipher primitive context. */
typedef int (*CIPHER_INIT)(CIPHER_PRIMITIVE_CONTEXT*, void*, size_t, void*);

/* Prototype for cipher primitive context forward and inverse updates. */
typedef void (*CIPHER_UPDATE)(CIPHER_PRIMITIVE_CONTEXT*, void*, size_t);

typedef void(*CIPHER_FREE)(CIPHER_PRIMITIVE_CONTEXT*);

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
    CIPHER_FREE fFree;
    /* The cipher primitive's name. */
    char* name;
} CIPHER_PRIMITIVE;

/*! Loads all primitivs. This must be called before you may use \c RC4(), \c NullCipher(), etc...
 * or the helper functions \c getCipherPrimitiveByName() and \c getCipherPrimitiveByID(). */
void primitivesLoad();

/*! The NullCipher cipher primitive. */
CIPHER_PRIMITIVE* NullCipher();

/*! The Threefish-256 cipher primitive. */
CIPHER_PRIMITIVE* Threefish256();

/*! The RC4 cipher primitive. */
CIPHER_PRIMITIVE* RC4();

/*! Returns a cipher primitive object from a name. */
CIPHER_PRIMITIVE* getCipherPrimitiveByName(char* name);

/*! Returns a cipher primitive object from an ID. */
CIPHER_PRIMITIVE* getCipherPrimitiveByID(size_t ID);

/*! This function returns an allocated cipher primitive context using a specific cipher primitive.
 \param primitive The primitive object to be used.
 \return Returns the allocated cipher primitive context, or 0 if an allocation error occurred. */
CIPHER_PRIMITIVE_CONTEXT* cipherCreate(CIPHER_PRIMITIVE* primitive);

/*! This function initializes an cipher primitive context for encryption, provided a key and cipher parameters.
 \param ctx An allocated cipher primitive context.
 \param key A pointer to a buffer containing the key to use for encryption.
 \param keySize The size, in bytes, of the encryption key.
 \param cipherParams This points to specific cipher parameters, set to zero for default behavior.
 \return Returns \c ORDO_ESUCCESS on success, and a negative value on error. */
int cipherInit(CIPHER_PRIMITIVE_CONTEXT* ctx, void* key, size_t keySize, void* cipherParams);

/*! This function frees (deallocates) an initialized cipher primitive context.
 \param ctx The cipher primitive context to be freed. This context needs to at least have been allocated.
 \remark Once this function returns, the passed context may no longer be used anywhere and sensitive information will be wiped.
 Passing zero to this function is invalid and will incur a segmentation fault. Do not call this function if \c cipherCreate failed. */
void cipherFree(CIPHER_PRIMITIVE_CONTEXT* ctx);

#endif
