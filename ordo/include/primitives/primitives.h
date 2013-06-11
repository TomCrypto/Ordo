#ifndef PRIMITIVES_H
#define PRIMITIVES_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file primitives.h
 *
 * \brief Cryptographic primitives.
 *
 * This declares all the cryptographic primitives in the library, abstracting various categories through high-level
 * interfaces.
 *
 * @see primitives.c
 */

/* Library dependencies. */
#include <common/ordotypes.h>

/* Macro to define a block cipher object. */
#define MAKE_BLOCK_CIPHER(p, b, c, i, pf, pi, f, n){                                                                  \
    p->blockSize = b;                                                                                                 \
    p->fCreate = c;                                                                                                   \
    p->fInit = (BLOCK_CIPHER_INIT)i;                                                                                  \
    p->fForward = (BLOCK_CIPHER_UPDATE)pf;                                                                            \
    p->fInverse = (BLOCK_CIPHER_UPDATE)pi;                                                                            \
    p->fFree = f;                                                                                                     \
    p->name = n;}

/* Same as above, but for stream ciphers. */
#define MAKE_STREAM_CIPHER(p, c, i, u, f, n){                                                                         \
    p->fCreate = c;                                                                                                   \
    p->fInit = (STREAM_CIPHER_INIT)i;                                                                                 \
    p->fUpdate = (STREAM_CIPHER_UPDATE)u;                                                                             \
    p->fFree = f;                                                                                                     \
    p->name = n;}

/* Same as above, but for hash functions. */
#define MAKE_HASH_FUNCTION(p, d, b, c, i, u, fi, f, n){                                                               \
    p->digestSize = d;                                                                                                \
    p->blockSize = b;                                                                                                 \
    p->fCreate = c;                                                                                                   \
    p->fInit = (HASH_FUNCTION_INIT)i;                                                                                 \
    p->fUpdate = (HASH_FUNCTION_UPDATE)u;                                                                             \
    p->fFinal = (HASH_FUNCTION_FINAL)fi;                                                                              \
    p->fFree = f;                                                                                                     \
    p->name = n;}

/*! Returns the name of a cryptographic primitive. */
#define primitiveName(p) (p->name)
/*! Returns the block size of a block cipher primitive. */
#define blockCipherBlockSize(p) (p->blockSize)
/*! Returns the digest size of a hash function primitive. */
#define hashFunctionDigestSize(p) (p->digestSize)

/*! \brief Block cipher context.
 *
 * This structure describes a block cipher primitive context. It is used by block cipher primitives to maintain their
 * state across function calls (this includes key material, in particular, and possibly parameters such as number of
 * rounds). It should never be modified outside of these functions and must be considered opaque. */
typedef struct BLOCK_CIPHER_CONTEXT
{
    /*! The block cipher in use. */
    struct BLOCK_CIPHER* cipher;
    /*! The low-level block cipher context. */
    void* ctx;
} BLOCK_CIPHER_CONTEXT;

/*! \brief Stream cipher context.
 *
 * This structure describes a stream cipher primitive context. It is used by stream ciphers to maintain their state
 * across function calls (usually, stream ciphers store their internal state there). */
typedef struct STREAM_CIPHER_CONTEXT
{
    /*! The stream cipher in use. */
    struct STREAM_CIPHER* cipher;
    /*! The low-level stream cipher context. */
    void* ctx;
} STREAM_CIPHER_CONTEXT;

/*! \brief hash function context.
 *
 * This structure describes a hash function primitive context. It is used by hash functions to maintain their state
 * across function calls (such as current message block and total length, extra metadata, etc...). */
typedef struct HASH_FUNCTION_CONTEXT
{
    /*! The hash function in use. */
    struct HASH_FUNCTION* hash;
    /*! The low-level hash function context. */
    void* ctx;
} HASH_FUNCTION_CONTEXT;

/* Block cipher interface function prototypes. */
typedef BLOCK_CIPHER_CONTEXT* (*BLOCK_CIPHER_ALLOC)();
typedef int (*BLOCK_CIPHER_INIT)(BLOCK_CIPHER_CONTEXT*, void*, size_t, void*);
typedef void (*BLOCK_CIPHER_UPDATE)(BLOCK_CIPHER_CONTEXT*, void*);
typedef void (*BLOCK_CIPHER_FREE)(BLOCK_CIPHER_CONTEXT*);

/*! \brief Block cipher object.
 *
 * This represents a block cipher object. */
typedef struct BLOCK_CIPHER
{
    size_t blockSize;
    BLOCK_CIPHER_ALLOC fCreate;
    BLOCK_CIPHER_INIT fInit;
    BLOCK_CIPHER_UPDATE fForward;
    BLOCK_CIPHER_UPDATE fInverse;
    BLOCK_CIPHER_FREE fFree;
    char* name;
} BLOCK_CIPHER;

/* Stream cipher interface function prototypes. */
typedef STREAM_CIPHER_CONTEXT* (*STREAM_CIPHER_ALLOC)();
typedef int (*STREAM_CIPHER_INIT)(STREAM_CIPHER_CONTEXT*, void*, size_t, void*);
typedef void (*STREAM_CIPHER_UPDATE)(STREAM_CIPHER_CONTEXT*, void*, size_t);
typedef void (*STREAM_CIPHER_FREE)(STREAM_CIPHER_CONTEXT*);

/*! \brief Stream cipher object.
 *
 * This represents a stream cipher object. */
typedef struct STREAM_CIPHER
{
    STREAM_CIPHER_ALLOC fCreate;
    STREAM_CIPHER_INIT fInit;
    STREAM_CIPHER_UPDATE fUpdate;
    STREAM_CIPHER_FREE fFree;
    char* name;
} STREAM_CIPHER;

/* Hash function interface function prototypes. */
typedef HASH_FUNCTION_CONTEXT* (*HASH_FUNCTION_ALLOC)();
typedef int (*HASH_FUNCTION_INIT)(HASH_FUNCTION_CONTEXT*, void*);
typedef void (*HASH_FUNCTION_UPDATE)(HASH_FUNCTION_CONTEXT*, void*, size_t);
typedef void (*HASH_FUNCTION_FINAL)(HASH_FUNCTION_CONTEXT*, void*);
typedef void (*HASH_FUNCTION_FREE)(HASH_FUNCTION_CONTEXT*);

/*! \brief Hash function object.
 *
 * This represents a hash function object. */
typedef struct HASH_FUNCTION
{
    size_t digestSize;
    size_t blockSize;
    HASH_FUNCTION_ALLOC fCreate;
    HASH_FUNCTION_INIT fInit;
    HASH_FUNCTION_UPDATE fUpdate;
    HASH_FUNCTION_FINAL fFinal;
    HASH_FUNCTION_FREE fFree;
    char* name;
} HASH_FUNCTION;

/*! Loads all primitives. This must be called before you may use \c RC4(), \c NullCipher(), etc... or the helper
 * functions \c getBlockCipherByName() or \c getStreamCipherByID(), etc... */
void primitivesLoad();

/*! The NullCipher block cipher. */
BLOCK_CIPHER* NullCipher();

/*! The Threefish-256 block cipher. */
BLOCK_CIPHER* Threefish256();

/*! The AES block cipher. */
BLOCK_CIPHER* AES();

/*! Returns a block cipher object from a name. */
BLOCK_CIPHER* getBlockCipherByName(char* name);

/*! Returns a block cipher object from an ID. */
BLOCK_CIPHER* getBlockCipherByID(size_t ID);

/*! The RC4 stream cipher. */
STREAM_CIPHER* RC4();

/*! Returns a stream cipher object from a name. */
STREAM_CIPHER* getStreamCipherByName(char* name);

/*! Returns a stream cipher object from an ID. */
STREAM_CIPHER* getStreamCipherByID(size_t ID);

/*! The SHA256 hash function. */
HASH_FUNCTION* SHA256();

/*! The MD5 hash function. */
HASH_FUNCTION* MD5();

/*! The Skein-256 hash function. */
HASH_FUNCTION* Skein256();

/*! Returns a hash function object from a name. */
HASH_FUNCTION* getHashFunctionByName(char* name);

/*! Returns a hash function object from an ID. */
HASH_FUNCTION* getHashFunctionByID(size_t ID);

/*! This function returns an allocated block cipher context using a given block cipher.
 \param cipher The block cipher to use.
 \return Returns the allocated block cipher context, or 0 if an error occurred. */
BLOCK_CIPHER_CONTEXT* blockCipherCreate(BLOCK_CIPHER* cipher);

/*! This function initializes a block cipher context for encryption, provided a key, and cipher parameters.
 \param ctx An allocated block cipher context.
 \param key A buffer containing the key to use for encryption.
 \param keySize The size, in bytes, of the encryption key.
 \param cipherParams This points to specific cipher parameters, set to zero for default behavior.
 \return Returns \c ORDO_ESUCCESS on success, and a negative value on error. */
int blockCipherInit(BLOCK_CIPHER_CONTEXT* ctx, void* key, size_t keySize, void* cipherParams);

/*! This function frees (deallocates) an initialized block cipher context.
 \param ctx The block cipher context to be freed. This context needs to at least have been allocated.
 \remark Once this function returns, the passed context may no longer be used anywhere and sensitive information will
 be wiped. Passing zero to this function is invalid and will incur a segmentation fault. Do not call this function if
 \c blockCipherCreate() failed, as the latter already works hard to ensure no memory is leaked if an error occurs. */
void blockCipherFree(BLOCK_CIPHER_CONTEXT* ctx);

/*! This function returns an allocated stream cipher context using a given stream cipher.
 \param cipher The stream cipher to use.
 \return Returns the allocated stream cipher context, or 0 if an error occurred. */
STREAM_CIPHER_CONTEXT* streamCipherCreate(STREAM_CIPHER* cipher);

/*! This function initializes a stream cipher context for encryption, provided a key and cipher parameters.
 \param ctx An allocated stream cipher context.
 \param key A buffer containing the key to use for encryption.
 \param keySize The size, in bytes, of the encryption key.
 \param cipherParams This points to specific cipher parameters, set to zero for default behavior.
 \return Returns \c ORDO_ESUCCESS on success, and a negative value on error. */
int streamCipherInit(STREAM_CIPHER_CONTEXT* ctx, void* key, size_t keySize, void* cipherParams);

/*! This function frees (deallocates) an initialized stream cipher context.
 \param ctx The stream cipher context to be freed. This context needs to at least have been allocated.
 \remark Once this function returns, the passed context may no longer be used anywhere and sensitive information will
 be wiped. Passing zero to this function is invalid and will incur a segmentation fault. Do not call this function if
 \c streamCipherCreate() failed, as the latter already works hard to ensure no memory is leaked if an error occurs. */
void streamCipherFree(STREAM_CIPHER_CONTEXT* ctx);

#ifdef __cplusplus
}
#endif

#endif
