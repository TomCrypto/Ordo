#ifndef ORDO_SHA256_H
#define ORDO_SHA256_H

#include <primitives/primitives.h>

/******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file sha256.h
 *
 * \brief SHA-256 hash function.
 *
 * This is the SHA-256 hash function, which produces a 256-bit digest.
 */

struct SHA256_STATE;

/*! Allocates and returns an uninitialized SHA-256 hash function context.
 @returns The allocated context, or nil on allocation failure.
*/
struct SHA256_STATE* sha256_alloc();

/*! Initializes an SHA-256 hash function context.
 @param ctx An allocated SHA-256 context.
 @param params Ignored.
 @returns Returns \c #ORDO_SUCCESS.
*/
int sha256_init(struct SHA256_STATE *state, const void* params);

/*! Feeds a buffer into the SHA-256 context, contributing to the final digest.
 @param ctx An initialized SHA-256 context.
 @param buffer A pointer to a buffer.
 @param size The amount of data, in bytes, to read from \c buffer.
 @remarks This function has the property that Update(A) followed by Update(B)
          is equivalent to Update(A || B) where || denotes concatenation.
*/
void sha256_update(struct SHA256_STATE *state, const void* buffer, size_t size);

/*! Retrieves the final digest from the SHA-256 context.
 @param ctx An initialized SHA-256 context.
 @param digest A buffer in which to write the digest.
 @remarks The buffer must be at least 16 bytes (128 bits) long.
 @remarks If this function is immediately called after \c sha256_init(), the
          result is the zero digest, that is, the digest corresponding to
          an input of length zero.
*/
void sha256_final(struct SHA256_STATE *state, void* digest);

/*! Frees the memory associated with the SHA-256 context.
 @param ctx An allocated SHA-256 context.
 @remarks The context need not have been initialized.
 @remarks Passing nil to this function is a no-op.
*/
void sha256_free(struct SHA256_STATE *state);

/*! Performs a deep copy of a context into another.
 @param dst The destination context.
 @param src The source context.
 @remarks Both contexts must have been allocated with \c sha256_alloc(). If a
          generic interface working for any hash function is required, use
          \c hashFunctionCopy().
*/
void sha256_copy(struct SHA256_STATE *dst, const struct SHA256_STATE *src);

/*! Populates a stream cipher object with the SHA-256 functions and
 *  attributes, and is meant for internal use.
 @param hash A pointer to a hash function object to populate.
 @remarks Once populated, the \c HASH_FUNCTION struct can be freely used in
          the higher level \c hash interface.
 @remarks If you have issued a call to \c load_primitives(), this function has
          already been called and you may use the \c SHA256() function to
          access the underlying SHA-256 hash function object.
 @see hash.h
 @internal
*/
void sha256_set_primitive(struct HASH_FUNCTION* hash);

#ifdef __cplusplus
}
#endif

#endif
