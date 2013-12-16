#ifndef ORDO_HASH_FUNCTIONS_H
#define ORDO_HASH_FUNCTIONS_H

#include "ordo/internal/api.h"

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
ORDO_API const char * ORDO_CALLCONV
hash_function_name(const struct HASH_FUNCTION *primitive);

/******************************************************************************/

/*! The SHA256 hash function. */
ORDO_API const struct HASH_FUNCTION * ORDO_CALLCONV
sha256(void);

/*! The MD5 hash function. */
ORDO_API const struct HASH_FUNCTION * ORDO_CALLCONV
md5(void);

/*! The Skein-256 hash function. */
ORDO_API const struct HASH_FUNCTION * ORDO_CALLCONV
skein256(void);

/******************************************************************************/

/*! Returns the number of hash functions available.
 *  @returns The number of available hash functions (at least one).
 *  @remarks This is for use in enumerating hash function ID's.
*/
ORDO_API size_t ORDO_CALLCONV
hash_function_count(void);

/*! Returns a hash function primitive from a name.
 *  @param name A hash function name.
 *  @returns The corresponding hash function primitive, or nil if no such
 *           hash function exists.
*/
ORDO_API const struct HASH_FUNCTION * ORDO_CALLCONV
hash_function_by_name(const char *name);

/*! Returns a hash function primitive from an index.
 *  @param index A hash function index.
 *  @returns The corresponding hash function primitive, or nil if no such
 *           hash function exists.
 *  @remarks Use \c hash_function_count() to get an upper bound on
 *           hash function indices.
*/
ORDO_API const struct HASH_FUNCTION * ORDO_CALLCONV
hash_function_by_index(size_t index);

/*! Returns a hash function primitive from a primitive ID.
 *  @param id A primitive ID.
 *  @returns The corresponding hash function primitive, or nil if no such
 *           hash function exists.
*/
ORDO_API const struct HASH_FUNCTION * ORDO_CALLCONV
hash_function_by_id(size_t id);

/******************************************************************************/

/*! Allocates a hash function state.
 *  @param primitive A hash function primitive.
 *  @returns Returns an allocated hash function state, or nil on error.
*/
ORDO_API void * ORDO_CALLCONV
hash_function_alloc(const struct HASH_FUNCTION *primitive);

/*! Initializes a hash function state.
 *  @param primitive A hash function primitive.
 *  @param state An allocated hash function state.
 *  @param params Hash function specific parameters.
 *  @returns Returns \c #ORDO_SUCCESS on success, or an error code.
*/
ORDO_API int ORDO_CALLCONV
hash_function_init(const struct HASH_FUNCTION *primitive,
                   void *state,
                   const void *params);

/*! Updates a hash function state by appending a buffer to the message
 *  to calculate the cryptographic digest of.
 *  @param primitive A hash function primitive.
 *  @param state An allocated hash function state.
 *  @param buffer A buffer to add to the message.
 *  @param len The length, in bytes, of the buffer.
*/
ORDO_API void ORDO_CALLCONV
hash_function_update(const struct HASH_FUNCTION *primitive,
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
ORDO_API void ORDO_CALLCONV
hash_function_final(const struct HASH_FUNCTION *primitive,
                    void *state,
                    void *digest);

/*! Frees a hash function state.
 *  @param primitive A hash function primitive.
 *  @param state A hash function state.
*/
ORDO_API void ORDO_CALLCONV
hash_function_free(const struct HASH_FUNCTION *primitive,
                   void *state);

/*! Copies a hash function state to another.
 *  @param primitive A hash function primitive.
 *  @param dst The destination state.
 *  @param src The source state.
 *  @remarks Both states must have been initialized with the same hash
 *           function and parameters.
*/
ORDO_API void ORDO_CALLCONV
hash_function_copy(const struct HASH_FUNCTION *primitive,
                   void *dst,
                   const void *src);

/*! Queries a hash function for suitable parameters.
 *  @param primitive A hash function primitive.
 *  @param query A query code.
 *  @param value A suggested value.
 *  @returns Returns a suitable parameter of type \c query based on \c value.
 *  @see query.h
*/
ORDO_API size_t ORDO_CALLCONV
hash_function_query(const struct HASH_FUNCTION *primitive,
                    int query, size_t value);

#ifdef __cplusplus
}
#endif

#endif
