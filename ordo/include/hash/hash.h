#ifndef ORDO_HASH_H
#define ORDO_HASH_H

#include <primitives/primitives.h>

/******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

struct HASH_CTX;

/**
 * @file hash.h
 *
 * \brief Hash function interface.
 *
 * Interface to compute cryptographic digests, using hash functions. This is
 * a very thin generic wrapper around the low-level functions.
*/

/*! Returns an allocated hash function context using a given hash function.
 \param hash The hash function to use.
 \return Returns the allocated hash function context, or nil if an allocation
         error occurred.
*/
struct HASH_CTX* hash_alloc(struct HASH_FUNCTION* hash);

/*! Initializes a hash function context, provided optional parameters.
 \param ctx An allocated hash function context.
 \param hashParams A pointer to specific hash function parameters, set to nil
                   for default behavior.
 \return Returns \c #ORDO_SUCCESS on success, and a negative value on error.
 \remarks It is always valid to pass nil for \c hashParams if you do not wish
          to use more advanced features offered by a specific hash function.
*/
int hash_init(struct HASH_CTX* ctx,
              void* hashParams);

/*! Feeds data into a hash function context, updating the final digest.
 \param ctx An allocated hash function context.
 \param buffer A buffer containing the data to hash.
 \param size The size, in bytes, of the data to read from \c buffer.
 \remarks This function has the property that Update(A) followed by Update(B)
          is equivalent to Update(A || B) where || denotes concatenation.
 */
void hash_update(struct HASH_CTX* ctx,
                 void* buffer, size_t size);

/*! Finalizes a hash function context, returning the final digest.
 \param ctx An allocated hash function context.
 \param digest A buffer into which the digest will be written.
 \remarks The \c digest buffer should be long enough to accomodate the digest.
          You can query the hash function's digest size in bytes via the
          \c hashDigestSize() macro.
*/
void hash_final(struct HASH_CTX* ctx,
                void* digest);

/*! Deallocates an initialized hash function context.
 \param ctx The hash function context to be freed.
 \remarks The context need not have been initialized.
 \remarks Passing nil to this function is a no-op.
 \remarks Once this function returns, the passed context may no longer be used
          anywhere, and any sensitive information will be wiped.
*/
void hash_free(struct HASH_CTX* ctx);

/*! Performs a deep copy of one context into another.
 \param dst The destination context.
 \param src The source context.
 \remarks Both contexts must have been allocated using the same hash function,
          else the function's behavior is undefined.
*/
void hash_copy(struct HASH_CTX* dst, struct HASH_CTX* src);

#ifdef __cplusplus
}
#endif

#endif
