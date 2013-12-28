//===-- primitives/block_ciphers.h ---------------------*- PUBLIC -*- H -*-===//
///
/// @file
/// @brief Abstraction Layer
///
/// This abstraction layer declares all the block ciphers, and also makes them
/// available to higher level modules. This does not actually do encryption at
/// all but simply abstracts block cipher permutations, the encryption modules
/// are in the \c enc folder: \c enc_block.h.
///
//===----------------------------------------------------------------------===//

#ifndef ORDO_BLOCK_CIPHERS_H
#define ORDO_BLOCK_CIPHERS_H

/// @cond
#include "ordo/common/interface.h"
#include "ordo/primitives/block_ciphers/block_params.h"
/// @endcond

#ifdef __cplusplus
extern "C" {
#endif

//===----------------------------------------------------------------------===//

struct BLOCK_CIPHER;

/// Returns the name of a block cipher primitive.
///
/// @param [in]     primitive      A block cipher primitive.
///
/// @returns Returns the block cipher's name.
///
/// @remarks This name can then be used in \c block_cipher_by_name().
ORDO_PUBLIC
const char *block_cipher_name(const struct BLOCK_CIPHER *primitive);

/// The NullCipher block cipher.
ORDO_PUBLIC
const struct BLOCK_CIPHER *nullcipher(void);

/// The Threefish-256 block cipher.
ORDO_PUBLIC
const struct BLOCK_CIPHER *threefish256(void);

/// The AES block cipher.
ORDO_PUBLIC
const struct BLOCK_CIPHER *aes(void);

/// Exposes the number of block ciphers available.
///
/// @returns The number of available block ciphers (at least one).
///
/// @remarks This is for use in enumerating block ciphers.
ORDO_PUBLIC
size_t block_cipher_count(void);

/// Returns a block cipher primitive from a name.
///
/// @param name A block cipher name.
///
/// @returns The block cipher such that the following is true:
///          @code block_cipher_name(retval) = name @endcode
///          or \c 0 if no such block cipher exists.
ORDO_PUBLIC
const struct BLOCK_CIPHER *block_cipher_by_name(const char *name);

/// Returns a block cipher primitive from an index.
///
/// @param [in]     index          A block cipher index.
///
/// @returns The block cipher corresponding to the  provided index, or \c 0 if
///          no such block cipher exists.
///
/// @remarks Use \c block_cipher_count() to get an upper bound on block cipher
///          indices (there will be at least one).
ORDO_PUBLIC
const struct BLOCK_CIPHER *block_cipher_by_index(size_t index);

//===----------------------------------------------------------------------===//

/// Allocates a block cipher state.
///
/// @param [in]     primitive      A block cipher primitive.
///
/// @returns An allocated block cipher state, or \c 0 on error.
ORDO_PUBLIC
void *block_cipher_alloc(const struct BLOCK_CIPHER *primitive);

/// Initializes a block cipher state.
///
/// @param [in]     primitive      A block cipher primitive.
/// @param [in,out] state          An allocated block cipher state.
/// @param [in]     key            The cryptographic key to use.
/// @param [in]     key_len        The length, in bytes, of the key.
/// @param [in]     params         Block cipher specific parameters.
///
/// @returns \c #ORDO_SUCCESS on success, else an error code.
ORDO_PUBLIC
int block_cipher_init(const struct BLOCK_CIPHER *primitive,
                      void *state,
                      const void *key,
                      size_t key_len,
                      const void *params);

/// Applies a block cipher's forward permutation.
///
/// @param [in]     primitive      A block cipher primitive.
/// @param [in]     state          An initialized block cipher state.
/// @param [in,out] block          A data block to permute.
///
/// @remarks The block should be the size of the block cipher's block size.
ORDO_PUBLIC
void block_cipher_forward(const struct BLOCK_CIPHER *primitive,
                          const void *state,
                          void *block);

/// Applies a block cipher's inverse permutation.
///
/// @param [in]     primitive      A block cipher primitive.
/// @param [in]     state          An initialized block cipher state.
/// @param [in,out] block          A data block to permute.
///
/// @remarks The block should be the size of the block cipher's block size.
ORDO_PUBLIC
void block_cipher_inverse(const struct BLOCK_CIPHER *primitive,
                          const void *state,
                          void *block);

/// Finalizes a block cipher state.
///
/// @param [in]     primitive      A block cipher primitive.
/// @param [in,out] state          A block cipher state.
ORDO_PUBLIC
void block_cipher_final(const struct BLOCK_CIPHER *primitive,
                        void *state);

/// Frees a block cipher state.
///
/// @param [in]     primitive      A block cipher primitive.
/// @param [in,out] state          A block cipher state.
ORDO_PUBLIC
void block_cipher_free(const struct BLOCK_CIPHER *primitive,
                       void *state);

/// Copies a block cipher state to another.
///
/// @param [in]     primitive      A block cipher primitive.
/// @param [out]    dst            The destination state.
/// @param [in]     src            The source state.
///
/// @remarks Both states must have been initialized with the same block cipher
///          and parameters, or this function's behaviour is undefined.
ORDO_PUBLIC
void block_cipher_copy(const struct BLOCK_CIPHER *primitive,
                       void *dst,
                       const void *src);

/// Queries a block cipher for suitable parameters.
///
/// @param [in]     primitive      A block cipher primitive.
/// @param [in]     query          A query code.
/// @param [in]     value          A suggested value.
///
/// @returns A suitable parameter of type \c query based on \c value.
///
/// @see query.h
ORDO_PUBLIC
size_t block_cipher_query(const struct BLOCK_CIPHER *primitive,
                          int query, size_t value);

//===----------------------------------------------------------------------===//

#ifdef __cplusplus
}
#endif

#endif
