#ifndef ORDO_DIGEST_H
#define ORDO_DIGEST_H

#include <primitives/primitives.h>

/******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * @file digest.h
 * @brief Cryptographic digest module.
 *
 * Module to compute cryptographic digests, using cryptographic hash function
 * primitives.
*/

/*! Digest context.
 *  @remarks This context must not be manipulated or operated on in any way
 *           outside the \c digest_* functions.
*/
struct DIGEST_CTX;

/*! Allocates a new digest context.
 @param hash The hash function to use.
 @return Returns the allocated digest context, or nil if an allocation error
         occurred.
*/
struct DIGEST_CTX* digest_alloc(const struct HASH_FUNCTION *hash);

/*! Initializes a digest context, provided optional parameters.
 @param ctx An allocated digest context.
 @param params A pointer to hash function specific parameters.
 @return Returns \c #ORDO_SUCCESS on success, and a negative value on error.
 @remarks It is always valid to pass nil for \c params if you do not wish
          to use more advanced features offered by a specific hash function.
*/
int digest_init(struct DIGEST_CTX *ctx,
                const void *params);

/*! Feeds data into a digest context.
 @param ctx An initialized digest context.
 @param buffer A buffer containing data to feed into the context.
 @param size The size, in bytes, of the data to read from \c buffer.
 @remarks This function has the property that \c update(x) followed by
          \c update(y) is equivalent to \c update(\c x \c || \c y) where
          \c || denotes concatenation.
*/
void digest_update(struct DIGEST_CTX *ctx,
                   const void *buffer,
                   size_t size);

/*! Finalizes a digest context, returning the digest of all data fed into it by
 *  \c digest_update calls.
 @param ctx An initialized digest context.
 @param digest A buffer into which the digest will be written.
 @remarks The \c digest buffer should be large enough to accomodate the digest.
          You can query the hash function's default digest length in bytes via
          the \c digest_length() function. If you provided parameters which
          modify the hash function's digest length, you should already know
          how long the digest will be (refer to the parameter documentation).
 @remarks Calling this function immediately after \c digest_init() is valid and
          will return the so-called `zero-length' digest, which is the digest
          of the input of length zero.
*/
void digest_final(struct DIGEST_CTX *ctx,
                  void *digest);

/*! Frees a digest context.
 @param ctx The digest context to be freed.
 @remarks The context need not have been initialized.
 @remarks Passing nil to this function is a no-op.
*/
void digest_free(struct DIGEST_CTX *ctx);

/*! Performs a deep copy of one context into another.
 @param dst The destination context.
 @param src The source context.
 @remarks Both contexts must have been allocated using the same hash function,
          with the exact same parameters (unless the parameter documentation
          states otherwise) else the function's behavior is undefined.
*/
void digest_copy(struct DIGEST_CTX *dst,
                 const struct DIGEST_CTX *src);

/*! Returns the default digest length of a hash function.
 @param hash A hash function primitive.
 @returns The length of the digest written in the \c digest parameter of
          \c digest_final(), if no parameters which affect output length
          were provided to \c digest_init().
*/
size_t digest_length(const struct HASH_FUNCTION *hash);

#ifdef __cplusplus
}
#endif

#endif
