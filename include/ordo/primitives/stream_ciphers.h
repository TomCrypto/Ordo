#ifndef ORDO_STREAM_CIPHERS_H
#define ORDO_STREAM_CIPHERS_H

#include <stdint.h>

#include "ordo/internal/api.h"

#include "ordo/primitives/stream_ciphers/stream_params.h"

/******************************************************************************/

/*!
 * @file stream_ciphers.h
 * @brief Stream cipher abstraction layer.
 *
 * <description here>
*/

#ifdef __cplusplus
extern "C" {
#endif

struct STREAM_CIPHER;

/******************************************************************************/

/*! Returns the name of a stream cipher primitive
 *  @param primitive A stream cipher primitive.
 *  @returns Returns the stream cipher's name.
 *  @remarks This name can then be used in \c stream_cipher_by_name().
*/
ORDO_API const char * ORDO_CALLCONV
stream_cipher_name(const struct STREAM_CIPHER *primitive);

/******************************************************************************/

/*! The RC4 stream cipher. */
ORDO_API const struct STREAM_CIPHER * ORDO_CALLCONV
rc4(void);

/******************************************************************************/

/*! Returns the number of stream ciphers available.
 *  @returns The number of available stream ciphers (at least one).
 *  @remarks This is for use in enumerating stream cipher ID's.
*/
ORDO_API size_t ORDO_CALLCONV
stream_cipher_count(void);

/*! Returns a stream cipher primitive from a name.
 *  @param name A stream cipher name.
 *  @returns The corresponding stream cipher primitive, or nil if no such
 *           stream cipher exists.
*/
ORDO_API const struct STREAM_CIPHER * ORDO_CALLCONV
stream_cipher_by_name(const char *name);

/*! Returns a stream cipher primitive from an index.
 *  @param index A stream cipher index.
 *  @returns The corresponding stream cipher primitive, or nil if no such
 *           stream cipher exists.
 *  @remarks Use \c stream_cipher_count() to get an upper bound on
 *           stream cipher indices.
*/
ORDO_API const struct STREAM_CIPHER * ORDO_CALLCONV
stream_cipher_by_index(size_t index);

/*! Returns a stream cipher primitive from a primitive ID.
 *  @param id A primitive ID.
 *  @returns The corresponding stream cipher primitive, or nil if no such
 *           stream cipher exists.
*/
ORDO_API const struct STREAM_CIPHER * ORDO_CALLCONV
stream_cipher_by_id(uint16_t id);

/******************************************************************************/

/*! Allocates a stream cipher state.
 *  @param primitive A stream cipher primitive.
 *  @returns Returns an allocated stream cipher state, or nil on error.
*/
ORDO_API void * ORDO_CALLCONV
stream_cipher_alloc(const struct STREAM_CIPHER *primitive);

/*! Initializes a stream cipher state.
 *  @param primitive A stream cipher primitive.
 *  @param state An allocated stream cipher state.
 *  @param key The cryptographic key to use.
 *  @param key_len The length, in bytes, of the key.
 *  @param params Stream cipher specific parameters.
 *  @returns Returns \c #ORDO_SUCCESS on success, or an error code.
*/
ORDO_API int ORDO_CALLCONV
stream_cipher_init(const struct STREAM_CIPHER *primitive,
                   void* state,
                   const void *key,
                   size_t key_len,
                   const void *params);

/*! Encrypts or decrypts a buffer using a stream cipher state.
 *  @param primitive A stream cipher primitive.
 *  @param state An allocated stream cipher state.
 *  @param buffer The buffer to encrypt or decrypt.
 *  @param len The length, in bytes, of the buffer.
 *  @remarks Encryption and decryption are equivalent, and are
 *           done in place.
 *  @remarks This function is stateful and will update the
 *           passed state (by generating keystream material),
 *           unlike block ciphers which are deterministic
 *           permutations.
*/
ORDO_API void ORDO_CALLCONV
stream_cipher_update(const struct STREAM_CIPHER *primitive,
                     void* state,
                     void *buffer,
                     size_t len);

/*! Frees a stream cipher state.
 *  @param primitive A stream cipher primitive.
 *  @param state A stream cipher state.
*/
ORDO_API void ORDO_CALLCONV
stream_cipher_free(const struct STREAM_CIPHER *primitive,
                   void *state);

/*! Copies a stream cipher state to another.
 *  @param primitive A stream cipher primitive.
 *  @param dst The destination state.
 *  @param src The source state.
 *  @remarks Both states must have been initialized with the same stream
 *           cipher and parameters.
*/
ORDO_API void ORDO_CALLCONV
stream_cipher_copy(const struct STREAM_CIPHER *primitive,
                   void *dst,
                   const void *src);

/*! Queries a stream cipher for suitable parameters.
 *  @param primitive A stream cipher primitive.
 *  @param query A query code.
 *  @param value A suggested value.
 *  @returns Returns a suitable parameter of type \c query based on \c value.
 *  @see query.h
*/
ORDO_API size_t ORDO_CALLCONV
stream_cipher_query(const struct STREAM_CIPHER *primitive,
                    int query, size_t value);

#ifdef __cplusplus
}
#endif

#endif
