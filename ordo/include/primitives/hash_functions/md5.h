#ifndef ORDO_MD5_H
#define ORDO_MD5_H

#include <primitives/primitives.h>

/******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file md5.h
 *
 * \brief MD5 hash function.
 *
 * This is the MD5 hash function, which produces a 128-bit digest.
 */

struct MD5_STATE;

/*! Allocates and returns an uninitialized MD5 hash function context.
 @returns The allocated context, or nil on allocation failure.
*/
struct MD5_STATE* md5_alloc();

/*! Initializes an MD5 hash function context.
 @param ctx An allocated MD5 context.
 @param params Ignored.
 @returns Returns \c #ORDO_SUCCESS.
*/
int md5_init(struct MD5_STATE *state, void* params);

/*! Feeds a buffer into the MD5 context, contributing to the final digest.
 @param ctx An initialized MD5 context.
 @param buffer A pointer to a buffer.
 @param size The amount of data, in bytes, to read from \c buffer.
 @remarks This function has the property that Update(A) followed by Update(B)
          is equivalent to Update(A || B) where || denotes concatenation.
*/
void md5_update(struct MD5_STATE *state, void* buffer, size_t size);

/*! Retrieves the final digest from the MD5 context.
 @param ctx An initialized MD5 context.
 @param digest A buffer in which to write the digest.
 @remarks The buffer must be at least 16 bytes (128 bits) long.
 @remarks If this function is immediately called after \c MD5_Init(), the
          result is the zero digest, that is, the digest corresponding to
          an input of length zero.
*/
void md5_final(struct MD5_STATE *state, void* digest);

/*! Frees the memory associated with the MD5 context.
 @param ctx An allocated MD5 context.
 @remarks The context need not have been initialized.
 @remarks Passing nil to this function is a no-op.
*/
void md5_free(struct MD5_STATE *state);

/*! Performs a deep copy of a context into another.
 @param dst The destination context.
 @param src The source context.
 @remarks Both contexts must have been allocated with \c md5_alloc(). If a
          generic interface working for any hash function is required, use
          \c hashFunctionCopy().
*/
void md5_copy(struct MD5_STATE *dst, struct MD5_STATE *src);

/*! Populates a stream cipher object with the MD5 functions and
 *  attributes, and is meant for internal use.
 @param hash A pointer to a hash function object to populate.
 @remarks Once populated, the \c HASH_FUNCTION struct can be freely used in
          the higher level \c hash interface.
 @remarks If you have issued a call to \c load_primitives(), this function has
          already been called and you may use the \c MD5() function to access
          the underlying MD5 hash function object.
 @see hash.h
 @internal
*/
void md5_set_primitive(struct HASH_FUNCTION* hash);

#ifdef __cplusplus
}
#endif

#endif
