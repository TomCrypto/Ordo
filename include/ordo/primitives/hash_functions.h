/*===-- primitives/hash_functions.h --------------------*- PUBLIC -*- H -*-===*/
/**
/// @file
/// @brief Abstraction Layer
///
/// This abstraction layer declares all the hash functions and also makes them
/// available to higher level modules - for a slightly more convenient wrapper
/// to this interface, you can use \c digest.h.
**/
/*===----------------------------------------------------------------------===*/

#ifndef ORDO_HASH_FUNCTIONS_H
#define ORDO_HASH_FUNCTIONS_H

/** @cond **/
#include "ordo/common/interface.h"
#include "ordo/primitives/hash_functions/hash_params.h"
/** @endcond **/

#ifdef __cplusplus
extern "C" {
#endif

/*===----------------------------------------------------------------------===*/

struct HASH_FUNCTION;

/** Returns the name of a hash function primitive.
///
/// @param [in]     primitive      A hash function primitive.
///
/// @returns Returns the hash function's name.
///
/// @remarks This name can then be used in \c hash_function_by_name().
**/
ORDO_PUBLIC
const char *hash_function_name(const struct HASH_FUNCTION *primitive);

/** The SHA-256 hash function.
**/
ORDO_PUBLIC
const struct HASH_FUNCTION *ordo_sha256(void);

/** The MD5 hash function.
**/
ORDO_PUBLIC
const struct HASH_FUNCTION *ordo_md5(void);

/** The Skein-256 hash function.
**/
ORDO_PUBLIC
const struct HASH_FUNCTION *ordo_skein256(void);

/** Returns a hash function primitive from a name.
///
/// @param name A hash function name.
///
/// @returns The hash function such that the following is true:
///          @code hash_function_name(retval) = name @endcode
///          or \c 0 if no such hash function exists.
**/
ORDO_PUBLIC
const struct HASH_FUNCTION *hash_function_by_name(const char *name);

/** Returns a hash function primitive from an index.
///
/// @param [in]     index          A hash function index.
///
/// @returns The hash function  corresponding to the  provided  index, or \c 0
///          if no such hash function exists.
///
/// @remarks Use \c hash_function_count() to  obtain an  upper  bound on  hash
///          function indices (there will be at least one).
**/
ORDO_PUBLIC
const struct HASH_FUNCTION *hash_function_by_index(size_t index);

/** Exposes the number of hash functions available.
///
/// @returns The number of available hash functions (at least one).
///
/// @remarks This is for use in enumerating hash functions.
**/
ORDO_PUBLIC
size_t hash_function_count(void);

/*===----------------------------------------------------------------------===*/

/** Initializes a hash function state.
///
/// @param [in]     primitive      A hash function primitive.
/// @param [in,out] state          An allocated hash function state.
/// @param [in]     params         Hash function specific parameters.
///
/// @returns \c #ORDO_SUCCESS on success, else an error code.
**/
ORDO_PUBLIC
int hash_function_init(const struct HASH_FUNCTION *primitive,
                       void *state,
                       const void *params);

/** Updates a hash  function state by  appending a buffer to the  message this
/// state is to calculate the cryptographic digest of.
///
/// @param [in]     primitive      A hash function primitive.
/// @param [in,out] state          A hash function state.
/// @param [in]     buffer         A buffer to append to the message.
/// @param [in]     len            The length, in bytes, of the buffer.
///
/// @remarks This function has the property that doing `update(x)` followed by
///          `update(y)` is equivalent to `update(x || y)`, where `||` denotes
///          concatenation.
**/
ORDO_PUBLIC
void hash_function_update(const struct HASH_FUNCTION *primitive,
                          void *state,
                          const void *buffer,
                          size_t len);

/** Finalizes a hash function state, outputting the final digest.
///
/// @param [in]     primitive      A hash function primitive.
/// @param [in,out] state          A hash function state.
/// @param [out]    digest         A buffer in which to write the digest.
///
/// @remarks The \c digest buffer should  be as  large as the  hash function's
///          digest length (unless you changed it via custom parameters).
**/
ORDO_PUBLIC
void hash_function_final(const struct HASH_FUNCTION *primitive,
                         void *state,
                         void *digest);

/** Performs a deep copy of one state into another.
///
/// @param [in]     primitive      A hash function primitive.
/// @param [out]    dst            The destination state.
/// @param [in]     src            The source state.
///
/// @remarks The destination state must have been allocated, by using the same
///          primitive(s) as the source state, and mustn't be initialized.
///
/// @remarks The source state must be initialized.
**/
ORDO_PUBLIC
void hash_function_copy(const struct HASH_FUNCTION *primitive,
                        void *dst,
                        const void *src);

/** Queries a hash function for suitable parameters.
///
/// @param [in]     primitive      A hash function primitive.
/// @param [in]     query          A query code.
/// @param [in]     value          A suggested value.
///
/// @returns A suitable parameter of type \c query based on \c value.
///
/// @see query.h
**/
ORDO_PUBLIC
size_t hash_function_query(const struct HASH_FUNCTION *primitive,
                           int query, size_t value);

/*===----------------------------------------------------------------------===*/

#ifdef __cplusplus
}
#endif

#endif
