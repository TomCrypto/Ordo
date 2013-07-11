#ifndef ORDO_SKEIN256_H
#define ORDO_SKEIN256_H

#include <primitives/primitives.h>

/******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * @file skein256.h
 * @brief Skein-256 hash function.
 *
 * This is the Skein-256 hash function, which produces a 256-bit digest by default (but has parameters to output a
 * longer digest) and has a 256-bit internal state. This implementation supports messages up to a length of 2^64 - 1
 * bytes instead of the 2^96 - 1 available, but we trust this will not be an issue. This is a rather flexible hash
 * with lots of options. The following features are marked [x] if available, [ ] otherwise:
 *
 * [x] Simple hashing (256-bit digest, any-length message) \n
 * [x] Variable-length output (any-length digest, any-length message, uses parameters) \n
 * [x] Semi-personalizable configuration block (everything is changeable, but generally you should only change the
 * output length field if you want to remain compliant) \n
 * [ ] Personalization block \n
 * [ ] HMAC block \n
 * [ ] Other blocks \n
 *
 * \todo Expand Skein-256 parameters (add possible extra blocks, such as personalization, hmac, nonce, etc...). This
 * will probably require a rewrite of the UBI subsystem which is rather hardcoded and rigid at the moment.
 *
 * \todo Rewrite the UBI code properly.
*/

struct SKEIN256_STATE;

/*! Allocates a Skein-256 state.
 @returns The allocated state, or nil on allocation failure.
*/
struct SKEIN256_STATE* skein256_alloc(void);

/*! Initializes a Skein-256 state.
 @param state An allocated SHA-256 state.
 @param params Pointer to Skein-256 parameters.
 @returns Returns \c #ORDO_SUCCESS.
*/
int skein256_init(struct SKEIN256_STATE *state,
                  const struct SKEIN256_PARAMS *params);

/*! Feeds a buffer into the Skein-256 state, contributing to the final digest.
 @param state An initialized Skein-256 state.
 @param buffer A buffer to feed into the Skein-256 state.
 @param len The length, in bytes, of the buffer.
 @remarks Refer to \c digest_update() for information on how the \c *_update
          functions behave.
*/
void skein256_update(struct SKEIN256_STATE *state,
                     const void *buffer,
                     size_t len);

/*! Retrieves the final digest from a Skein-256 state.
 @param state An initialized Skein-256 state.
 @param digest A buffer in which to write the digest.
 @remarks The buffer must be at least 32 bytes (256 bits) long if the
          \c output_length parameter passed to \c skein256_init() does not
          indicate otherwise.
 @remarks If this function is immediately called after \c skein256_init(),
          the result is the zero digest, that is, the digest corresponding
          to an input of length zero.
 @remarks One must call \c skein256_init() to reuse the state after this
          function is called. It is an error to call \c skein256_update()
          immediately after.
*/
void skein256_final(struct SKEIN256_STATE *state,
                    void *digest);

/*! Frees a Skein-256 state.
 @param state An allocated Skein-256 state.
 @remarks The state need not have been initialized.
 @remarks Passing nil to this function is a no-op.
*/
void skein256_free(struct SKEIN256_STATE *state);

/*! Performs a deep copy of a state into another.
 @param dst The destination state.
 @param src The source state.
 @remarks The two states must have been initialized with the same parameters,
          unless the documentation of \c SKEIN256_PARAMS states otherwise.
*/
void skein256_copy(struct SKEIN256_STATE *dst,
                   const struct SKEIN256_STATE *src);

/*! Populates a stream cipher object with the Skein-256 functions and
 *  attributes, and is meant for internal use.
 @param hash A pointer to a hash function object to populate.
 @remarks Once populated, the \c HASH_FUNCTION struct can be freely used in
          the higher level \c hash interface.
 @remarks If you have issued a call to \c load_primitives(), this function has
          already been called and you may use the \c Skein256() function to
          access the underlying Skein-256 hash function object.
 @see digest.h
 @internal
*/
void skein256_set_primitive(struct HASH_FUNCTION *hash);

#ifdef __cplusplus
}
#endif

#endif
