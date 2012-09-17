#ifndef PRIMITIVES_H
#define PRIMITIVES_H

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

/* Useful macro to define a block cipher object. */
#define MAKE_BLOCK_CIPHER(p, b, c, i, pf, pi, f, n){                                                                          \
    p->blockSize = b;                                                                                                         \
    p->fCreate = c;                                                                                                           \
    p->fInit = (BLOCK_CIPHER_INIT)i;                                                                                          \
    p->fForward = (BLOCK_CIPHER_UPDATE)pf;                                                                                    \
    p->fInverse = (BLOCK_CIPHER_UPDATE)pi;                                                                                    \
    p->fFree = f;                                                                                                             \
    p->name = n;}

/* Same as above, but for stream ciphers. */
#define MAKE_STREAM_CIPHER(p, c, i, u, f, n){                                                                                 \
    p->fCreate = c;                                                                                                           \
    p->fInit = (STREAM_CIPHER_INIT)i;                                                                                         \
    p->fUpdate = (STREAM_CIPHER_UPDATE)u;                                                                                     \
    p->fFree = f;                                                                                                             \
    p->name = n;}

/*! Returns the name of a primitive. */
#define primitiveName(p) (p->name)
/*! Returns the block size of a cipher primitive. */
#define blockCipherBlockSize(p) (p->blockSize)

/*! \brief Block cipher context.
 *
 * This structure describes a cipher primitive context. It is used by
 * cipher primitives to maintain their state across function calls (this
 * includes key material and/or actual state for stream ciphers).
 * It should never be modified outside of these functions. */
typedef struct BLOCK_CIPHER_CONTEXT
{
    /*! The cipher primitive in use. */
    struct BLOCK_CIPHER* cipher;
    /*! The low-level cipher primitive context. */
    void* ctx;
} BLOCK_CIPHER_CONTEXT;

/*! \brief Stream cipher context.
 *
 * This structure describes a cipher primitive context. It is used by
 * cipher primitives to maintain their state across function calls (this
 * includes key material and/or actual state for stream ciphers).
 * It should never be modified outside of these functions. */
typedef struct STREAM_CIPHER_CONTEXT
{
    /*! The cipher primitive in use. */
    struct STREAM_CIPHER* cipher;
    /*! The low-level cipher primitive context. */
    void* ctx;
} STREAM_CIPHER_CONTEXT;

/* Prototype for allocating and freeing cipher primitive contexts. */
typedef BLOCK_CIPHER_CONTEXT* (*BLOCK_CIPHER_ALLOC)(struct BLOCK_CIPHER*);

/* Prototype for initializing a cipher primitive context. */
typedef int (*BLOCK_CIPHER_INIT)(BLOCK_CIPHER_CONTEXT*, void*, size_t, void*);

/* Prototype for cipher primitive context forward and inverse updates. */
typedef void (*BLOCK_CIPHER_UPDATE)(BLOCK_CIPHER_CONTEXT*, void*);

typedef void(*BLOCK_CIPHER_FREE)(BLOCK_CIPHER_CONTEXT*);

/* This structure defines a symmetric cipher primitive. */
typedef struct BLOCK_CIPHER
{
    /* The block size, in bytes, of the cipher primitive. */
    size_t blockSize;
    /* Points to the cipher primitive context creation function. */
    BLOCK_CIPHER_ALLOC fCreate;
    /* Points to the cipher primitive context initialization function. */
    BLOCK_CIPHER_INIT fInit;
    /* Points to the cipher primitive context forward update function. */
    BLOCK_CIPHER_UPDATE fForward;
    /* Points to the cipher primitive context inverse update function. */
    BLOCK_CIPHER_UPDATE fInverse;
    /* Points to the cipher primitive context free function. */
    BLOCK_CIPHER_FREE fFree;
    /* The cipher primitive's name. */
    char* name;
} BLOCK_CIPHER;

/* Prototype for allocating and freeing cipher primitive contexts. */
typedef STREAM_CIPHER_CONTEXT* (*STREAM_CIPHER_ALLOC)(struct STREAM_CIPHER*);

/* Prototype for initializing a cipher primitive context. */
typedef int (*STREAM_CIPHER_INIT)(STREAM_CIPHER_CONTEXT*, void*, size_t, void*);

/* Prototype for cipher primitive context forward and inverse updates. */
typedef void (*STREAM_CIPHER_UPDATE)(STREAM_CIPHER_CONTEXT*, void*, size_t);

typedef void(*STREAM_CIPHER_FREE)(STREAM_CIPHER_CONTEXT*);

/* This structure defines a symmetric cipher primitive. */
typedef struct STREAM_CIPHER
{
    /* Points to the cipher primitive context creation function. */
    STREAM_CIPHER_ALLOC fCreate;
    /* Points to the cipher primitive context initialization function. */
    STREAM_CIPHER_INIT fInit;
    /* Points to the cipher primitive context forward update function. */
    STREAM_CIPHER_UPDATE fUpdate;
    /* Points to the cipher primitive context free function. */
    STREAM_CIPHER_FREE fFree;
    /* The cipher primitive's name. */
    char* name;
} STREAM_CIPHER;

/*! Loads all primitivs. This must be called before you may use \c RC4(), \c NullCipher(), etc...
 * or the helper functions \c getCipherPrimitiveByName() and \c getCipherPrimitiveByID(). */
void primitivesLoad();

/*! The NullCipher cipher primitive. */
BLOCK_CIPHER* NullCipher();

/*! The Threefish-256 cipher primitive. */
BLOCK_CIPHER* Threefish256();

/*! Returns a block cipher primitive object from a name. */
BLOCK_CIPHER* getBlockCipherByName(char* name);

/*! Returns a block cipher primitive object from an ID. */
BLOCK_CIPHER* getBlockCipherByID(size_t ID);

STREAM_CIPHER* RC4();

/*! Returns a stream cipher primitive object from a name. */
STREAM_CIPHER* getStreamCipherByName(char* name);

/*! Returns a stream cipher primitive object from an ID. */
STREAM_CIPHER* getStreamCipherByID(size_t ID);

/*! This function returns an allocated cipher primitive context using a specific cipher primitive.
 \param primitive The primitive object to be used.
 \return Returns the allocated cipher primitive context, or 0 if an allocation error occurred. */
BLOCK_CIPHER_CONTEXT* blockCipherCreate(BLOCK_CIPHER* cipher);

/*! This function initializes an cipher primitive context for encryption, provided a key and cipher parameters.
 \param ctx An allocated cipher primitive context.
 \param key A pointer to a buffer containing the key to use for encryption.
 \param keySize The size, in bytes, of the encryption key.
 \param cipherParams This points to specific cipher parameters, set to zero for default behavior.
 \return Returns \c ORDO_ESUCCESS on success, and a negative value on error. */
int blockCipherInit(BLOCK_CIPHER_CONTEXT* ctx, void* key, size_t keySize, void* cipherParams);

/*! This function frees (deallocates) an initialized cipher primitive context.
 \param ctx The cipher primitive context to be freed. This context needs to at least have been allocated.
 \remark Once this function returns, the passed context may no longer be used anywhere and sensitive information will be wiped.
 Passing zero to this function is invalid and will incur a segmentation fault. Do not call this function if \c cipherCreate failed. */
void blockCipherFree(BLOCK_CIPHER_CONTEXT* ctx);

/*! This function returns an allocated cipher primitive context using a specific cipher primitive.
 \param primitive The primitive object to be used.
 \return Returns the allocated cipher primitive context, or 0 if an allocation error occurred. */
STREAM_CIPHER_CONTEXT* streamCipherCreate(STREAM_CIPHER* cipher);

/*! This function initializes an cipher primitive context for encryption, provided a key and cipher parameters.
 \param ctx An allocated cipher primitive context.
 \param key A pointer to a buffer containing the key to use for encryption.
 \param keySize The size, in bytes, of the encryption key.
 \param cipherParams This points to specific cipher parameters, set to zero for default behavior.
 \return Returns \c ORDO_ESUCCESS on success, and a negative value on error. */
int streamCipherInit(STREAM_CIPHER_CONTEXT* ctx, void* key, size_t keySize, void* cipherParams);

/*! This function frees (deallocates) an initialized cipher primitive context.
 \param ctx The cipher primitive context to be freed. This context needs to at least have been allocated.
 \remark Once this function returns, the passed context may no longer be used anywhere and sensitive information will be wiped.
 Passing zero to this function is invalid and will incur a segmentation fault. Do not call this function if \c cipherCreate failed. */
void streamCipherFree(STREAM_CIPHER_CONTEXT* ctx);

#endif
