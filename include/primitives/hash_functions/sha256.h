#ifndef ORDO_SHA256_H
#define ORDO_SHA256_H

#include <primitives/primitives.h>

/******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * @file sha256.h
 * @brief SHA-256 hash function.
 *
 * The SHA-256 hash function, which produces a 256-bit digest.
*/

struct SHA256_STATE;

/*! Allocates a SHA-256 state.
 @returns The allocated state, or nil on allocation failure.
*/
struct SHA256_STATE* sha256_alloc(void);

/*! Initializes a SHA-256 state.
 @param state An allocated SHA-256 state.
 @param params Ignored, as SHA-256 has no parameters.
 @returns Returns \c #ORDO_SUCCESS.
*/
int sha256_init(struct SHA256_STATE *state,
                const void *params);

/*! Feeds a buffer into the SHA-256 state, contributing to the final digest.
 @param state An initialized SHA-256 state.
 @param buffer A buffer to feed into the SHA-256 state.
 @param len The length, in bytes, of the buffer.
 @remarks Refer to \c digest_update() for information on how the \c *_update
          functions behave.
*/
void sha256_update(struct SHA256_STATE *state,
                   const void *buffer,
                   size_t len);

/*! Retrieves the final digest from a SHA-256 state.
 @param state An initialized SHA-256 state.
 @param digest A buffer in which to write the digest.
 @remarks The buffer must be at least 32 bytes (256 bits) long.
 @remarks If this function is immediately called after \c sha256_init(), the
          result is the zero digest, that is, the digest corresponding to an
          input of length zero.
 @remarks One must call \c sha256_init() to reuse the state after this
          function is called. It is an error to call \c sha256_update()
          immediately after.
*/
void sha256_final(struct SHA256_STATE *state,
                  void *digest);

/*! Frees a SHA-256 state.
 @param state An allocated SHA-256 state.
 @remarks The state need not have been initialized.
 @remarks Passing nil to this function is a no-op.
*/
void sha256_free(struct SHA256_STATE *state);

/*! Performs a deep copy of a state into another.
 @param dst The destination state.
 @param src The source state.
*/
void sha256_copy(struct SHA256_STATE *dst,
                 const struct SHA256_STATE *src);

/*! Populates a stream cipher object with the SHA-256 functions and attributes,
 *  and is meant for internal use.
 @param hash A pointer to a hash function object to populate.
 @remarks Once populated, the \c HASH_FUNCTION struct can be freely used in
          the higher level \c hash interface.
 @remarks If you have issued a call to \c load_primitives(), this function has
          already been called and you may use the \c SHA256() function to access
          the underlying SHA-256 hash function object.
 @see digest.h
 @internal
*/
void sha256_set_primitive(struct HASH_FUNCTION* hash);

#ifdef __cplusplus
}
#endif

#endif
