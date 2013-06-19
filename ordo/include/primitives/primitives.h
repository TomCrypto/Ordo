#ifndef ORDO_PRIMITIVES_H
#define ORDO_PRIMITIVES_H

#include <stdint.h>
#include <stdlib.h>

/******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file primitives.h
 *
 * \brief Cryptographic primitives.
 *
 * This declares all the cryptographic primitives in the library, abstracting
 * various types of primitives (block ciphers, hash functions, etc..) through
 * higher level interfaces.
 */

/* Headers containing the primitive parameter structures, such that they do not
 * require to be explicitly included for every different primitive in use. */
#include <primitives/block_ciphers/block_params.h>
#include <primitives/stream_ciphers/stream_params.h>
#include <primitives/hash_functions/hash_params.h>

/* Block cipher interface function prototypes. */
typedef void* (*BLOCK_ALLOC)();
typedef int (*BLOCK_INIT)(void*, void*, size_t, void*);
typedef void (*BLOCK_UPDATE)(void*, void*);
typedef void (*BLOCK_FREE)(void*);

/* Stream cipher interface function prototypes. */
typedef void* (*STREAM_ALLOC)();
typedef int (*STREAM_INIT)(void*, void*, size_t, void*);
typedef void (*STREAM_UPDATE)(void*, void*, size_t);
typedef void (*STREAM_FREE)(void*);

/* Hash function interface function prototypes. */
typedef void* (*HASH_ALLOC)();
typedef int (*HASH_INIT)(void*, void*);
typedef void (*HASH_UPDATE)(void*, void*, size_t);
typedef void (*HASH_FINAL)(void*, void*);
typedef void (*HASH_FREE)(void*);
typedef void (*HASH_COPY)(void*, void*);

struct BLOCK_CIPHER;
struct STREAM_CIPHER;
struct HASH_FUNCTION;

void make_block_cipher(struct BLOCK_CIPHER *primitive, size_t block_size,
                       BLOCK_ALLOC alloc, BLOCK_INIT init, BLOCK_UPDATE forward,
                       BLOCK_UPDATE inverse, BLOCK_FREE free, char *name);

void make_stream_cipher(struct STREAM_CIPHER *primitive,
                       STREAM_ALLOC alloc, STREAM_INIT init, STREAM_UPDATE update,
                       STREAM_FREE free, char *name);

void make_hash_function(struct HASH_FUNCTION *primitive, size_t digest_length, size_t block_size,
                       HASH_ALLOC alloc, HASH_INIT init, HASH_UPDATE update,
                       HASH_FINAL final, HASH_FREE free, HASH_COPY copy, char *name);

const char* block_cipher_name(struct BLOCK_CIPHER *primitive);
const char* stream_cipher_name(struct STREAM_CIPHER *primitive);
const char* hash_function_name(struct HASH_FUNCTION *primitive);

size_t cipher_block_size(struct BLOCK_CIPHER *primitive);
size_t hash_digest_length(struct HASH_FUNCTION *primitive);
size_t hash_block_size(struct HASH_FUNCTION *primitive);

/*! Loads all primitives. This must be called before you may use \c RC4(),
 * \c NullCipher(), etc... or the helper functions \c block_cipher_by_name()
 * or \c stream_cipher_by_id(), and so on. */
void load_primitives();

/*! The NullCipher block cipher. */
struct BLOCK_CIPHER* NullCipher();

/*! The Threefish-256 block cipher. */
struct BLOCK_CIPHER* Threefish256();

/*! The AES block cipher. */
struct BLOCK_CIPHER* AES();

/*! Returns a block cipher object from a name. */
struct BLOCK_CIPHER* block_cipher_by_name(char* name);

/*! Returns a block cipher object from an ID. */
struct BLOCK_CIPHER* block_cipher_by_id(size_t id);

/*! The RC4 stream cipher. */
struct STREAM_CIPHER* RC4();

/*! Returns a stream cipher object from a name. */
struct STREAM_CIPHER* stream_cipher_by_name(char* name);

/*! Returns a stream cipher object from an ID. */
struct STREAM_CIPHER* stream_cipher_by_id(size_t id);

/*! The SHA256 hash function. */
struct HASH_FUNCTION* SHA256();

/*! The MD5 hash function. */
struct HASH_FUNCTION* MD5();

/*! The Skein-256 hash function. */
struct HASH_FUNCTION* Skein256();

/*! Returns a hash function object from a name. */
struct HASH_FUNCTION* hash_function_by_name(char* name);

/*! Returns a hash function object from an ID. */
struct HASH_FUNCTION* hash_function_by_id(size_t id);

/* BLOCK CIPHER ABSTRACTION LAYER. */

void* block_cipher_alloc(struct BLOCK_CIPHER* primitive);
int block_cipher_init(struct BLOCK_CIPHER* primitive, void *ctx, void *key, size_t key_size, void *params);
void block_cipher_forward(struct BLOCK_CIPHER* primitive, void *ctx, void *block);
void block_cipher_inverse(struct BLOCK_CIPHER* primitive, void *ctx, void *block);
void block_cipher_free(struct BLOCK_CIPHER* primitive, void *ctx);

/* STREAM CIPHER ABSTRACTION LAYER. */

void* stream_cipher_alloc(struct STREAM_CIPHER *primitive);
int stream_cipher_init(struct STREAM_CIPHER *primitive, void* ctx, void *key, size_t key_size, void *params);
void stream_cipher_update(struct STREAM_CIPHER *primitive, void* ctx, void *buffer, size_t size);
void stream_cipher_free(struct STREAM_CIPHER *primitive, void *ctx);

/* HASH FUNCTION ABSTRACTION LAYER. */

void* hash_function_alloc(struct HASH_FUNCTION *primitive);
int hash_function_init(struct HASH_FUNCTION *primitive, void *ctx, void *params);
void hash_function_update(struct HASH_FUNCTION *primitive, void *ctx, void *buffer, size_t size);
void hash_function_final(struct HASH_FUNCTION *primitive, void *ctx, void *digest);
void hash_function_free(struct HASH_FUNCTION *primitive, void *ctx);
void hash_function_copy(struct HASH_FUNCTION *primitive, void *dst, void *src);

#ifdef __cplusplus
}
#endif

#endif
