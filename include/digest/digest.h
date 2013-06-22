#ifndef ORDO_DIGEST_H
#define ORDO_DIGEST_H

#include <primitives/primitives.h>

/******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

struct DIGEST_CTX;

/**
 * @file digest.h
 *
 * \brief Cryptographic digest module.
 *
 * Module to compute cryptographic digests, using hash functions.
*/

/*! Returns an allocated hash function context using a given hash function.
 \param hash The hash function to use.
 \return Returns the allocated hash function context, or nil if an allocation
         error occurred.
*/
struct DIGEST_CTX* digest_alloc(struct HASH_FUNCTION* hash);

/*! Initializes a hash function context, provided optional parameters.
 \param ctx An allocated hash function context.
 \param hashParams A pointer to specific hash function parameters, set to nil
                   for default behavior.
 \return Returns \c #ORDO_SUCCESS on success, and a negative value on error.
 \remarks It is always valid to pass nil for \c hashParams if you do not wish
          to use more advanced features offered by a specific hash function.
*/
int digest_init(struct DIGEST_CTX* ctx,
                void* hashParams);

/*! Feeds data into a hash function context, updating the final digest.
 \param ctx An allocated hash function context.
 \param buffer A buffer containing the data to hash.
 \param size The size, in bytes, of the data to read from \c buffer.
 \remarks This function has the property that Update(A) followed by Update(B)
          is equivalent to Update(A || B) where || denotes concatenation.
 */
void digest_update(struct DIGEST_CTX* ctx,
                   void* buffer, size_t size);

/*! Finalizes a hash function context, returning the final digest.
 \param ctx An allocated hash function context.
 \param digest A buffer into which the digest will be written.
 \remarks The \c digest buffer should be long enough to accomodate the digest.
          You can query the hash function's digest size in bytes via the
          \c hashDigestSize() macro.
*/
void digest_final(struct DIGEST_CTX* ctx,
                  void* digest);

/*! Deallocates an initialized hash function context.
 \param ctx The hash function context to be freed.
 \remarks The context need not have been initialized.
 \remarks Passing nil to this function is a no-op.
 \remarks Once this function returns, the passed context may no longer be used
          anywhere, and any sensitive information will be wiped.
*/
void digest_free(struct DIGEST_CTX* ctx);

/*! Performs a deep copy of one context into another.
 \param dst The destination context.
 \param src The source context.
 \remarks Both contexts must have been allocated using the same hash function,
          else the function's behavior is undefined.
*/
void digest_copy(struct DIGEST_CTX* dst, struct DIGEST_CTX* src);

#ifdef __cplusplus
}
#endif

#endif
