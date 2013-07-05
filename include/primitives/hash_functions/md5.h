#ifndef ORDO_MD5_H
#define ORDO_MD5_H

#include <primitives/primitives.h>

/******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * @file md5.h
 * @brief MD5 hash function.
 *
 * The MD5 hash function, which produces a 128-bit digest.
*/

struct MD5_STATE;

/*! Allocates an MD5 state.
 @returns The allocated state, or nil on allocation failure.
*/
struct MD5_STATE* md5_alloc();

/*! Initializes an MD5 state.
 @param state An allocated MD5 state.
 @param params Ignored, as MD5 has no parameters.
 @returns Returns \c #ORDO_SUCCESS.
*/
int md5_init(struct MD5_STATE *state,
             const void *params);

/*! Feeds a buffer into the MD5 state, contributing to the final digest.
 @param state An initialized MD5 state.
 @param buffer A buffer to feed into the MD5 state.
 @param len The length, in bytes, of the buffer.
 @remarks Refer to \c digest_update() for information on how the \c *_update
          functions behave.
*/
void md5_update(struct MD5_STATE *state,
                const void *buffer,
                size_t len);

/*! Retrieves the final digest from a MD5 state.
 @param state An initialized MD5 state.
 @param digest A buffer in which to write the digest.
 @remarks The buffer must be at least 16 bytes (128 bits) long.
 @remarks If this function is immediately called after \c md5_init(), the
          result is the zero digest, that is, the digest corresponding to
          an input of length zero.
 @remarks One must call \c md5_init() to reuse the state after this function is
          called. It is an error to call \c md5_update() immediately after.
*/
void md5_final(struct MD5_STATE *state,
               void *digest);

/*! Frees an MD5 state.
 @param state An allocated MD5 state.
 @remarks The state need not have been initialized.
 @remarks Passing nil to this function is a no-op.
*/
void md5_free(struct MD5_STATE *state);

/*! Performs a deep copy of a v into another.
 @param dst The destination state.
 @param src The source state.
*/
void md5_copy(struct MD5_STATE *dst,
              const struct MD5_STATE *src);

/*! Populates a stream cipher object with the MD5 functions and attributes, and
 *  is meant for internal use.
 @param hash A pointer to a hash function object to populate.
 @remarks Once populated, the \c HASH_FUNCTION struct can be freely used in
          the higher level \c hash interface.
 @remarks If you have issued a call to \c load_primitives(), this function has
          already been called and you may use the \c MD5() function to access
          the underlying MD5 hash function object.
 @see digest.h
 @internal
*/
void md5_set_primitive(struct HASH_FUNCTION* hash);

#ifdef __cplusplus
}
#endif

#endif
