#ifndef ORDO_HMAC_H
#define ORDO_HMAC_H

#include "ordo/digest/digest.h"

/******************************************************************************/

/*!
 * @file hmac.h
 * @brief HMAC module.
 *
 * Module for computing HMAC's (Hash-based Message Authentication Codes), which
 * securely combine a hash function with a cryptographic key securely in order
 * to provide both authentication and integrity, as per RFC 2104.
 *
 * This module follows the usual flow diagram:
 *
 * @code
 *      +--------------------------------------------------+
 *      |                      +----+                      |
 *      |                      |    |                      |
 *    +-|-----+   +------+   +-v----|-+   +-------+   +----v-+
 *    | alloc |-->| init |-->| update |-->| final |-->| free |
 *    +-------+   +-|----+   +--------+   +-----|-+   +------+
 *                  |                           |
 *                  +---------------------------+
 * @endcode
 *
 * Copying a digest context - via \c hmac_copy() - is meaningful only when
 * following \c hmac_init() and preceding \c hmac_final().
*/

#ifdef __cplusplus
extern "C" {
#endif

struct HMAC_CTX;

/*! Allocates a new HMAC context.
 *  @param hash The hash function to use.
 *  @return Returns the allocated HMAC context, or nil if an error occurred.
 *  @remarks The PRF used for the HMAC will be the hash function as it behaves
 *           with default parameters. It is not possible to use hash function
 *           extensions (e.g. Skein in specialized HMAC mode) via this module.
*/
struct HMAC_CTX *hmac_alloc(const struct HASH_FUNCTION *hash);

/*! Initializes an HMAC context, provided optional parameters.
 *  @param ctx An allocated HMAC context.
 *  @param key The cryptographic key to use.
 *  @param key_len The size, in bytes, of the key.
 *  @param params Hash function specific parameters.
 *  @return Returns \c #ORDO_SUCCESS on success, or an error code.
 *  @remarks The hash parameters apply to the inner hash function only (the one
 *           used to hash the passed key with the inner mask).
 *  @remarks Do not use hash parameters which modify the hash function's output
 *           length, or this function's behavior is undefined.
*/
int hmac_init(struct HMAC_CTX *ctx,
              const void *key, size_t key_len,
              const void *params);

/*! Updates an HMAC context, feeding more data into it.
 *  @param ctx An allocated HMAC context.
 *  @param in A pointer to data to feed into the context.
 *  @param in_len The amount of bytes of data to read from \c buffer.
 *  @remarks This function has the same property with respect to the input
 *           buffer as \c digest_update().
*/
void hmac_update(struct HMAC_CTX *ctx, const void *in, size_t in_len);

/*! Finalizes a HMAC context, returning the final digest.
 *  @param ctx An allocated HMAC context.
 *  @param digest A pointer to a buffer to which the digest will be written.
 *  @return Returns \c #ORDO_SUCCESS on success, or an error code.
 *  @remarks The digest length is equal to the underlying hash function's
 *           digest length, which may be queried via \c hash_digest_length().
*/
int hmac_final(struct HMAC_CTX *ctx, void *digest);

/*! Frees an HMAC context.
 *  @param ctx An allocated HMAC context.
 *  @remarks Passing nil to this function is valid and will do nothing.
*/
void hmac_free(struct HMAC_CTX *ctx);

/*! Deep-copies a context to another.
 *  @param dst The destination context.
 *  @param src The source context.
 *  @remarks Both contexts need to have been initialized with the same hash
 *           function and the exact same parameters, or this function's
 *           behavior is undefined.
*/
void hmac_copy(struct HMAC_CTX *dst, const struct HMAC_CTX *src);

#ifdef __cplusplus
}
#endif

#endif
