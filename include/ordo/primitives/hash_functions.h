#ifndef ORDO_HASH_FUNCTIONS_H
#define ORDO_HASH_FUNCTIONS_H

#include "ordo/primitives/hash_functions/hash_params.h"

/******************************************************************************/

/*!
 * @file hash_functions.h
 * @brief Hash function abstraction layer.
 *
 * <description here>
*/

#ifdef __cplusplus
extern "C" {
#endif

struct HASH_FUNCTION;

/******************************************************************************/

/*! Returns the name of a hash function primitive
 *  @param primitive A hash function primitive.
 *  @returns Returns the hash function's name.
 *  @remarks This name can then be used in \c hash_function_by_name().
*/
const char *hash_function_name(const struct HASH_FUNCTION *primitive);

/******************************************************************************/

/*! The SHA256 hash function. */
const struct HASH_FUNCTION *sha256(void);

/*! The MD5 hash function. */
const struct HASH_FUNCTION *md5(void);

/*! The Skein-256 hash function. */
const struct HASH_FUNCTION *skein256(void);

/******************************************************************************/

/*! Returns the number of hash functions available.
 *  @returns The number of available hash functions (at least one).
 *  @remarks This is for use in enumerating hash function ID's.
*/
size_t hash_function_count(void);

/*! Returns a hash function primitive from a name.
 *  @param name A hash function name.
 *  @returns The corresponding hash function primitive, or nil if no such
 *           hash function exists.
*/
const struct HASH_FUNCTION *hash_function_by_name(const char *name);

/*! Returns a hash function primitive from an ID.
 *  @param id A hash function ID.
 *  @returns The corresponding hash function primitive, or nil if no such
 *           hash function exists.
 *  @remarks Use \c hash_function_count() to get an upper bound on
 *           hash function ID's.
*/
const struct HASH_FUNCTION *hash_function_by_id(size_t id);

/******************************************************************************/

/*! Allocates a hash function state.
 *  @param primitive A hash function primitive.
 *  @returns Returns an allocated hash function state, or nil on error.
*/
void* hash_function_alloc(const struct HASH_FUNCTION *primitive);

/*! Initializes a hash function state.
 *  @param primitive A hash function primitive.
 *  @param state An allocated hash function state.
 *  @param params Hash function specific parameters.
 *  @returns Returns \c #ORDO_SUCCESS on success, or an error code.
*/
int hash_function_init(const struct HASH_FUNCTION *primitive,
                       void *state,
                       const void *params);

/*! Updates a hash function state by appending a buffer to the message
 *  to calculate the cryptographic digest of.
 *  @param primitive A hash function primitive.
 *  @param state An allocated hash function state.
 *  @param buffer A buffer to add to the message.
 *  @param len The length, in bytes, of the buffer.
*/
void hash_function_update(const struct HASH_FUNCTION *primitive,
                          void *state,
                          const void *buffer,
                          size_t len);

/*! Finalizes a hash function state, outputting the final digest.
 *  @param primitive A hash function primitive.
 *  @param state An allocated hash function state.
 *  @param digest A buffer in which to write the digest.
 *  @remarks The \c digest buffer should be as large as the hash function's
 *           digest length (default length, unless you changed it via
 *           parameters).
*/
void hash_function_final(const struct HASH_FUNCTION *primitive,
                         void *state,
                         void *digest);

/*! Frees a hash function state.
 *  @param primitive A hash function primitive.
 *  @param state A hash function state.
*/
void hash_function_free(const struct HASH_FUNCTION *primitive,
                        void *state);

/*! Copies a hash function state to another.
 *  @param primitive A hash function primitive.
 *  @param dst The destination state.
 *  @param src The source state.
 *  @remarks Both states must have been initialized with the same hash
 *           function and parameters.
*/
void hash_function_copy(const struct HASH_FUNCTION *primitive,
                        void *dst,
                        const void *src);

/*! Queries a hash function for suitable parameters.
 *  @param primitive A hash function primitive.
 *  @param query A query code.
 *  @param value A suggested value.
 *  @returns Returns a suitable parameter of type \c query based on \c value.
 *  @see query.h
*/
size_t hash_function_query(const struct HASH_FUNCTION *primitive,
                           int query, size_t value);

#ifdef __cplusplus
}
#endif

#endif
