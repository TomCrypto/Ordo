#ifndef ORDO_HMAC_H
#define ORDO_HMAC_H

#include <digest/digest.h>

/******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * @file hmac.h
 * @brief HMAC module.
 *
 * Module for computing HMAC's (Hash-based Message Authentication Codes), which
 * securely combine a hash function with a cryptographic key securely in order
 * to provide both authentication and integrity, as per RFC 2104.
*/

struct HMAC_CTX;

/*! Allocates a new HMAC context.
 @param hash The hash function to use.
 @return Returns the allocated HMAC context, or nil if an error occurred.
 @remarks The PRF used for the HMAC will be the hash function as it behaves
          with default parameters. It is not possible to use hash function
          extensions (e.g. Skein in specialized HMAC mode) via this module.
*/
struct HMAC_CTX* hmac_alloc(const struct HASH_FUNCTION *hash);

/*! Initializes an HMAC context, provided optional parameters.
 @param ctx An allocated HMAC context.
 @param key The cryptographic key to use.
 @param key_size The size, in bytes, of the key.
 @param hash_params Hash function specific parameters.
 @return Returns \c #ORDO_SUCCESS on success, and a negative value on error.
 @remarks The hash parameters apply to the inner hash function only (the one
          used to hash the passed key with the inner mask).
 @remarks Do not use hash parameters which modify the hash function's output
          length, or this function's behavior is undefined.
*/
int hmac_init(struct HMAC_CTX *ctx,
              const void *key,
              size_t key_size,
              const void *hash_params);

/*! Updates an HMAC context, feeding more data into it.
 @param ctx An allocated HMAC context.
 @param buffer A pointer to data to feed into the context.
 @param size The amount of bytes of data to read from \c buffer.
 @remarks This function has the property that calling it in succession with
          buffers A and B is equivalent to calling it once by concatenating
          A and B together.
*/
void hmac_update(struct HMAC_CTX *ctx,
                 const void *buffer,
                 size_t size);

/*! Finalizes a HMAC context, returning the final digest.
 @param ctx An allocated HMAC context.
 @param digest A pointer to a buffer where the digest will be written.
 @return Returns \c #ORDO_SUCCESS on success, and a negative value on error.
 @remarks The digest length is equal to the underlying hash function's digest
          length, which may be queried via \c hash_digest_length().
*/
int hmac_final(struct HMAC_CTX *ctx,
               void *digest);

/*! Frees an HMAC context.
 @param ctx An allocated HMAC context.
 @remarks Passing nil to this function is a no-op.
*/
void hmac_free(struct HMAC_CTX *ctx);

/*! Deep-copies a context to another.
 @param dst The destination context.
 @param src The source context.
 @remarks Both contexts need to have been allocated with the same hash function
          and (if initialized, which is likely) the same hash parameters (since
          parameters can affect the underlying hash function's state) unless
          the documentation indicates otherwise.
          
*/
void hmac_copy(struct HMAC_CTX *dst,
               const struct HMAC_CTX *src);

#ifdef __cplusplus
}
#endif

#endif
