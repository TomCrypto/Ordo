#ifndef ORDO_BLOCK_CIPHERS_H
#define ORDO_BLOCK_CIPHERS_H

#include <stdint.h>

#include "ordo/internal/api.h"

#include "ordo/primitives/block_ciphers/block_params.h"

/******************************************************************************/

/*!
 * @file block_ciphers.h
 * @brief Block cipher abstraction layer.
 *
 * <description here>
*/

#ifdef __cplusplus
extern "C" {
#endif

struct BLOCK_CIPHER;

/******************************************************************************/

/*! Returns the name of a block cipher primitive
 *  @param primitive A block cipher primitive.
 *  @returns Returns the block cipher's name.
 *  @remarks This name can then be used in \c block_cipher_by_name().
*/
ORDO_API const char * ORDO_CALLCONV
block_cipher_name(const struct BLOCK_CIPHER *primitive);

/******************************************************************************/

/*! The NullCipher block cipher. */
ORDO_API const struct BLOCK_CIPHER * ORDO_CALLCONV
nullcipher(void);

/*! The Threefish-256 block cipher. */
ORDO_API const struct BLOCK_CIPHER * ORDO_CALLCONV
threefish256(void);

/*! The AES block cipher. */
ORDO_API const struct BLOCK_CIPHER * ORDO_CALLCONV
aes(void);

/******************************************************************************/

/*! Returns the number of block ciphers available.
 *  @returns The number of available block ciphers (at least one).
 *  @remarks This is for use in enumerating block cipher ID's.
*/
ORDO_API size_t ORDO_CALLCONV
block_cipher_count(void);

/*! Returns a block cipher primitive from a name.
 *  @param name A block cipher name.
 *  @returns The corresponding block cipher primitive, or nil if no such
 *           block cipher exists.
*/
ORDO_API const struct BLOCK_CIPHER * ORDO_CALLCONV
block_cipher_by_name(const char *name);

/*! Returns a block cipher primitive from an index.
 *  @param index A block cipher index.
 *  @returns The corresponding block cipher primitive, or nil if no such
 *           block cipher exists.
 *  @remarks Use \c block_cipher_count() to get an upper bound on
 *           block cipher indices.
*/
ORDO_API const struct BLOCK_CIPHER * ORDO_CALLCONV
block_cipher_by_index(size_t index);

/*! Returns a block cipher primitive from a primitive ID.
 *  @param id A primitive ID.
 *  @returns The corresponding block cipher primitive, or nil if no such
 *           block cipher exists.
*/
ORDO_API const struct BLOCK_CIPHER * ORDO_CALLCONV
block_cipher_by_id(uint16_t id);

/******************************************************************************/

/*! Allocates a block cipher state.
 *  @param primitive A block cipher primitive.
 *  @returns Returns an allocated block cipher state, or nil on error.
*/
ORDO_API void * ORDO_CALLCONV
block_cipher_alloc(const struct BLOCK_CIPHER *primitive);

/*! Initializes a block cipher state.
 *  @param primitive A block cipher primitive.
 *  @param state An allocated block cipher state.
 *  @param key The cryptographic key to use.
 *  @param key_len The length, in bytes, of the key.
 *  @param params Block cipher specific parameters.
 *  @returns Returns \c #ORDO_SUCCESS on success, or an error code.
*/
ORDO_API int ORDO_CALLCONV
block_cipher_init(const struct BLOCK_CIPHER *primitive,
                  void *state,
                  const void *key,
                  size_t key_len,
                  const void *params);

/*! Applies a block cipher's forward permutation.
 *  @param primitive A block cipher primitive.
 *  @param state An initialized block cipher state.
 *  @param block A data block to permute.
 *  @remarks The block should be the size of the block cipher's
 *           block size.
*/
ORDO_API void ORDO_CALLCONV
block_cipher_forward(const struct BLOCK_CIPHER *primitive,
                     void *state,
                     void *block);

/*! Applies a block cipher's inverse permutation.
 *  @param primitive A block cipher primitive.
 *  @param state An initialized block cipher state.
 *  @param block A data block to permute.
 *  @remarks The block should be the size of the block cipher's
 *           block size.
*/
ORDO_API void ORDO_CALLCONV
block_cipher_inverse(const struct BLOCK_CIPHER *primitive,
                     void *state,
                     void *block);

/*! Frees a block cipher state.
 *  @param primitive A block cipher primitive.
 *  @param state A block cipher state.
*/
ORDO_API void ORDO_CALLCONV
block_cipher_free(const struct BLOCK_CIPHER *primitive,
                  void *state);

/*! Copies a block cipher state to another.
 *  @param primitive A block cipher primitive.
 *  @param dst The destination state.
 *  @param src The source state.
 *  @remarks Both states must have been initialized with the same block
 *           cipher and parameters.
*/
ORDO_API void ORDO_CALLCONV
block_cipher_copy(const struct BLOCK_CIPHER *primitive,
                  void *dst,
                  const void *src);

/*! Queries a block cipher for suitable parameters.
 *  @param primitive A block cipher primitive.
 *  @param query A query code.
 *  @param value A suggested value.
 *  @returns Returns a suitable parameter of type \c query based on \c value.
 *  @see query.h
*/
ORDO_API size_t ORDO_CALLCONV
block_cipher_query(const struct BLOCK_CIPHER *primitive,
                   int query, size_t value);

#ifdef __cplusplus
}
#endif

#endif
