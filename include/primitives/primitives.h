#ifndef ORDO_PRIMITIVES_H
#define ORDO_PRIMITIVES_H

#include <stdint.h>
#include <stdlib.h>

#include <primitives/block_ciphers/block_params.h>
#include <primitives/stream_ciphers/stream_params.h>
#include <primitives/hash_functions/hash_params.h>

/******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file primitives.h
 * @brief Cryptographic primitive abstraction layer.
 *
 * This declares all the cryptographic primitives in the library, abstracting
 * various types of primitives (block ciphers, hash functions, etc..) through
 * higher level interfaces.
 *
 * It is not strictly needed to use this abstraction layer, as you can directly
 * access the primitive functions from their respective headers, but as all the
 * other modules rely on it, it would be very inefficient to do so.
*/

typedef void* (*BLOCK_ALLOC)  (                                       );
typedef  int  (*BLOCK_INIT)   (void*, const void*, size_t, const void*);
typedef void  (*BLOCK_UPDATE) (void*,       void*                     );
typedef void  (*BLOCK_FREE)   (void*                                  );
typedef void  (*BLOCK_COPY)   (void*, const void*                     );

typedef void* (*STREAM_ALLOC)  (                                       );
typedef  int  (*STREAM_INIT)   (void*, const void*, size_t, const void*);
typedef void  (*STREAM_UPDATE) (void*,       void*, size_t             );
typedef void  (*STREAM_FREE)   (void*                                  );
typedef void  (*STREAM_COPY)   (void*, const void*                     );

typedef void* (*HASH_ALLOC)  (                          );
typedef  int  (*HASH_INIT)   (void*, const void*        );
typedef void  (*HASH_UPDATE) (void*, const void*, size_t);
typedef void  (*HASH_FINAL)  (void*, void*              );
typedef void  (*HASH_FREE)   (void*                     );
typedef void  (*HASH_COPY)   (void*, const void*        );

/*! Block cipher primitive.
 @remarks This should be considered opaque, and should be used only through
          the abstraction layer.
*/ 
struct BLOCK_CIPHER;

/*! Stream cipher primitive.
 @remarks Same remark as for \c BLOCK_CIPHER.
*/
struct STREAM_CIPHER;

/*! Hash function primitive.
 @remarks Same remark as for \c BLOCK_CIPHER.
*/
struct HASH_FUNCTION;

/*! Constructs a block cipher primitive.
 @param primitive A block cipher primitive to be created.
 @param block_size The block cipher's size.
 @param alloc The allocation function.
 @param init The initialization function.
 @param forward The forward permutation.
 @param inverse The inverse permutation.
 @param free The deallocation function.
 @param copy The state copy function.
 @param name The block cipher's name.
 @remarks This is used internally, but can be used from outside the library. So
          one can theoretically implement a block cipher via this interface and
          then be able to use it in any module requiring a \c BLOCK_CIPHER
          primitive (if you do, you might consider submitting it for inclusion
          in the library).
 @remarks The block cipher's key size is conspicuously absent. This is because
          this abstraction layer supports variable-length keys.
*/
void make_block_cipher(struct BLOCK_CIPHER *primitive,
                       size_t block_size,
                       BLOCK_ALLOC alloc,
                       BLOCK_INIT init,
                       BLOCK_UPDATE forward,
                       BLOCK_UPDATE inverse,
                       BLOCK_FREE free,
                       BLOCK_COPY copy,
                       const char *name);

/*! Constructs a stream cipher primitive.
 @param primitive A stream cipher primitive to be created.
 @param alloc The allocation function.
 @param init The initialization function.
 @param update The update function (generates keystream and encrypts data).
 @param free The deallocation function.
 @param copy The state copy function.
 @param name The stream cipher's name.
 @remarks Same remark as for \c make_block_cipher().
*/
void make_stream_cipher(struct STREAM_CIPHER *primitive,
                        STREAM_ALLOC alloc,
                        STREAM_INIT init,
                        STREAM_UPDATE update,
                        STREAM_FREE free,
                        STREAM_COPY copy,
                        const char *name);

/*! Constructs a hash function primitive.
 @param primitive A hash function primitive to be created.
 @param digest_length The hash function's digest length.
 @param block_size The hash function's block size (this isn't often used but
                   some modules such as HMAC require it).
 @param alloc The allocation function.
 @param init The initialization function.
 @param update The update function (is fed data and updates state).
 @param final The finalization function (outputs final digest).
 @param free The deallocation function.
 @param copy The state copy function.
 @param name The hash function's name.
 @remarks Same remark as for \c make_block_cipher().
 @remarks The hash function's digest length must be constant. Ordo does in
          fact support variable-length output, however modules based on the
          hash function abstraction layer will almost always assume the
          default digest length and will explicitly require you to not
          pass parameters which may affect the hash function's output
          length.
*/
void make_hash_function(struct HASH_FUNCTION *primitive,
                        size_t digest_length,
                        size_t block_size,
                        HASH_ALLOC alloc,
                        HASH_INIT init,
                        HASH_UPDATE update,
                        HASH_FINAL final,
                        HASH_FREE free,
                        HASH_COPY copy,
                        const char *name);

/******************************************************************************/

/*! Returns the name of a block cipher primitive. */
const char* block_cipher_name(const struct BLOCK_CIPHER *primitive);

/*! Returns the name of a stream cipher primitive. */
const char* stream_cipher_name(const struct STREAM_CIPHER *primitive);

/*! Returns the name of a hash function primitive. */
const char* hash_function_name(const struct HASH_FUNCTION *primitive);

/*! Returns the block size of a block cipher primitive. */
size_t cipher_block_size(const struct BLOCK_CIPHER *primitive);

/*! Returns the digest length of a hash function primitive. */
size_t hash_digest_length(const struct HASH_FUNCTION *primitive);

/*! Returns the block size of a hash function primitive. */
size_t hash_block_size(const struct HASH_FUNCTION *primitive);

/******************************************************************************/

/*! Loads all primitives provided by the library.
 @remarks This must be called before you may use \c RC4(), \c MD5(), etc...
          or the helper functions \c block_cipher_by_name(),
          \c stream_cipher_by_id(), and so on.
*/
void load_primitives();

/*! The NullCipher block cipher. */
const struct BLOCK_CIPHER* NullCipher();

/*! The Threefish-256 block cipher. */
const struct BLOCK_CIPHER* Threefish256();

/*! The AES block cipher. */
const struct BLOCK_CIPHER* AES();

/*! The RC4 stream cipher. */
const struct STREAM_CIPHER* RC4();

/*! The SHA256 hash function. */
const struct HASH_FUNCTION* SHA256();

/*! The MD5 hash function. */
const struct HASH_FUNCTION* MD5();

/*! The Skein-256 hash function. */
const struct HASH_FUNCTION* Skein256();

/******************************************************************************/

/*! Returns a block cipher primitive from a name. */
const struct BLOCK_CIPHER* block_cipher_by_name(const char *name);

/*! Returns a stream cipher primitive from a name. */
const struct STREAM_CIPHER* stream_cipher_by_name(const char *name);

/*! Returns a hash function primitive from a name. */
const struct HASH_FUNCTION* hash_function_by_name(const char *name);

/*! Returns a block cipher primitive from an ID. */
const struct BLOCK_CIPHER* block_cipher_by_id(size_t id);

/*! Returns a stream cipher primitive from an ID. */
const struct STREAM_CIPHER* stream_cipher_by_id(size_t id);

/*! Returns a hash function primitive from an ID. */
const struct HASH_FUNCTION* hash_function_by_id(size_t id);

/******************************************************************************/

void* block_cipher_alloc(const struct BLOCK_CIPHER *primitive);

int block_cipher_init(const struct BLOCK_CIPHER *primitive,
                      void *state,
                      const void *key,
                      size_t key_size,
                      const void *params);

void block_cipher_forward(const struct BLOCK_CIPHER *primitive,
                          void *state,
                          void *block);

void block_cipher_inverse(const struct BLOCK_CIPHER *primitive,
                          void *state,
                          void *block);

void block_cipher_free(const struct BLOCK_CIPHER *primitive,
                       void *state);

void block_cipher_copy(const struct BLOCK_CIPHER *primitive,
                       void *dst,
                       const void *src);

void* stream_cipher_alloc(const struct STREAM_CIPHER *primitive);

int stream_cipher_init(const struct STREAM_CIPHER *primitive,
                       void* state,
                       const void *key,
                       size_t key_size,
                       const void *params);

void stream_cipher_update(const struct STREAM_CIPHER *primitive,
                          void* state,
                          void *buffer,
                          size_t size);

void stream_cipher_free(const struct STREAM_CIPHER *primitive,
                        void *state);

void stream_cipher_copy(const struct STREAM_CIPHER *primitive,
                        void *dst,
                        const void *src);

void* hash_function_alloc(const struct HASH_FUNCTION *primitive);

int hash_function_init(const struct HASH_FUNCTION *primitive,
                       void *state,
                       const void *params);

void hash_function_update(const struct HASH_FUNCTION *primitive,
                          void *state,
                          const void *buffer,
                          size_t size);

void hash_function_final(const struct HASH_FUNCTION *primitive,
                         void *state,
                         void *digest);

void hash_function_free(const struct HASH_FUNCTION *primitive,
                        void *state);

void hash_function_copy(const struct HASH_FUNCTION *primitive,
                        void *dst,
                        const void *src);

size_t hash_function_length(const struct HASH_FUNCTION *primitive,
                            const void *params);

#ifdef __cplusplus
}
#endif

#endif
