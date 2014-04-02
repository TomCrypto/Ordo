//===-- enc/block_modes.h ------------------------------*- PUBLIC -*- H -*-===//
///
/// @file
/// @brief Abstraction Layer
///
/// This abstraction  layer declares all the  block modes of operation  in the
/// library, making them available to higher level modules.
///
/// Note "block cipher mode of operation" is shortened to "block mode" in code
/// and documentation to minimize noise and redundancy.
///
//===----------------------------------------------------------------------===//

#ifndef ORDO_BLOCK_MODES_H
#define ORDO_BLOCK_MODES_H

/// @cond
#include "ordo/common/interface.h"
#include "ordo/primitives/block_modes/mode_params.h"
/// @endcond

#include "ordo/primitives/block_ciphers.h"

#ifdef __cplusplus
extern "C" {
#endif

//===----------------------------------------------------------------------===//

struct BLOCK_MODE;

/// Returns the name of a block mode primitive.
///
/// @param [in]     mode           A block mode primitive.
///
/// @returns Returns the block mode's name.
///
/// @remarks This name can then be used in \c block_mode_by_name().
ORDO_PUBLIC
const char *block_mode_name(const struct BLOCK_MODE *mode);

/// The ECB (Electronic CodeBook) block mode of operation.
ORDO_PUBLIC
const struct BLOCK_MODE *ordo_ecb(void);

/// The CBC (Ciphertext Block Chaining) block mode of operation.
ORDO_PUBLIC
const struct BLOCK_MODE *ordo_cbc(void);

/// The CTR (CounTeR) block mode of operation.
ORDO_PUBLIC
const struct BLOCK_MODE *ordo_ctr(void);

/// The CFB (Cipher FeedBack) block mode of operation.
ORDO_PUBLIC
const struct BLOCK_MODE *ordo_cfb(void);

/// The OFB (Output FeedBack) block mode of operation.
ORDO_PUBLIC
const struct BLOCK_MODE *ordo_ofb(void);

/// Returns a block mode primitive from a name.
///
/// @param name A block mode name.
///
/// @returns The block mode such that the following is true:
///          @code block_mode_name(retval) = name @endcode
///          or \c 0 if no such block mode exists.
ORDO_PUBLIC
const struct BLOCK_MODE *block_mode_by_name(const char* name);

/// Returns a block cipher mode from an index.
///
/// @param [in]     index          A block mode index.
///
/// @returns The block mode corresponding to the provided index, or \c 0 if no
///          no such block mode exists.
///
/// @remarks Use \c block_mode_count() to get an upper bound on the block mode
///          indices (there will be at least one).
ORDO_PUBLIC
const struct BLOCK_MODE *block_mode_by_index(size_t index);

/// Exposes the number of block modes available.
///
/// @returns The number of available block modes (at least one).
///
/// @remarks This is for use in enumerating block modes.
ORDO_PUBLIC
size_t block_mode_count(void);

//===----------------------------------------------------------------------===//

/// Allocates a block mode state.
///
/// @param [in]     mode           A block mode primitive.
/// @param [in]     cipher         A block cipher primitive.
/// @param [in]     cipher_state   An allocated block cipher state.
///
/// @returns An allocated block mode state, or \c 0 on error.
ORDO_PUBLIC
void *block_mode_alloc(const struct BLOCK_MODE *mode,
                       const struct BLOCK_CIPHER *cipher,
                       const void *cipher_state);

/// Initializes a block mode state.
///
/// @param [in]     mode           A block mode primitive.
/// @param [in,out] state          A block mode state.
/// @param [in]     cipher         A block cipher primitive.
/// @param [in]     cipher_state   A block cipher state.
/// @param [in]     iv             The initialization vector to use.
/// @param [in]     iv_len         The length, in bytes, of the IV.
/// @param [in]     direction      1 for encryption, 0 for decryption.
/// @param [in]     params         Block mode specific parameters.
///
/// @returns \c #ORDO_SUCCESS on success, else an error code.
ORDO_PUBLIC
int block_mode_init(const struct BLOCK_MODE *mode,
                    void *state,
                    const struct BLOCK_CIPHER *cipher,
                    const void *cipher_state,
                    const void *iv, size_t iv_len,
                    int direction,
                    const void *params);

/// Encrypts or decrypts a buffer.
///
/// @param [in]     mode           A block mode primitive.
/// @param [in,out] state          A block mode state.
/// @param [in]     cipher         A block cipher primitive.
/// @param [in]     cipher_state   A block cipher state.
/// @param [in]     in             The input buffer.
/// @param [in]     in_len         The length, in bytes, of the input.
/// @param [out]    out            The output buffer.
/// @param [out]    out_len        A pointer to an  integer to  which to write
///                                the  number of  output  bytes  that  can be
///                                returned to the user. Remaining  input data
///                                has \b not been ignored  and should  not be
///                                passed again.
///
/// @remarks In-place  encryption (by  letting \c in be the  same buffer as \c
///          out) may not be supported by \c mode, check the documentation.
ORDO_PUBLIC
void block_mode_update(const struct BLOCK_MODE *mode,
                       void *state,
                       const struct BLOCK_CIPHER *cipher,
                       const void *cipher_state,
                       const void *in, size_t in_len,
                       void *out, size_t *out_len);

/// Finalizes a block mode state.
///
/// @param [in]     mode           A block mode primitive.
/// @param [in,out] state          A block mode state.
/// @param [in]     cipher         A block cipher primitive.
/// @param [in]     cipher_state   A block cipher state.
/// @param [out]    out            The output buffer.
/// @param [out]    out_len        A  pointer to an  integer to which to store
///                                the number of bytes written to \c out.
///
/// @returns \c #ORDO_SUCCESS on success, else an error code.
///
/// @remarks This function will return any input bytes which were not returned
///          by calls to \c block_mode_update() (in the correct order).
ORDO_PUBLIC
int block_mode_final(const struct BLOCK_MODE *mode,
                     void *state,
                     const struct BLOCK_CIPHER *cipher,
                     const void* cipher_state,
                     void *out, size_t *out_len);

/// Frees a block mode state.
///
/// @param [in]     mode           A block mode primitive.
/// @param [in,out] state          A block mode state.
/// @param [in]     cipher         A block cipher primitive.
/// @param [in]     cipher_state   A block cipher state.
ORDO_PUBLIC
void block_mode_free(const struct BLOCK_MODE *mode,
                     void *state,
                     const struct BLOCK_CIPHER *cipher,
                     const void *cipher_state);

/// Performs a deep copy of one state into another.
///
/// @param [in]     mode           A block mode primitive.
/// @param [in]     cipher         A block cipher primitive.
/// @param [out]    dst            The destination state.
/// @param [in]     src            The source state.
///
/// @remarks The destination state must have been allocated, by using the same
///          primitive(s) as the source state, and mustn't be initialized.
///
/// @remarks The source state must be initialized.
ORDO_PUBLIC
void block_mode_copy(const struct BLOCK_MODE *mode,
                     const struct BLOCK_CIPHER *cipher,
                     void *dst,
                     const void *src);

/// Queries a block mode for suitable parameters.
///
/// @param [in]     mode           A block mode primitive.
/// @param [in]     cipher         A block cipher primitive.
/// @param [in]     query          A query code.
/// @param [in]     value          A suggested value.
///
/// @returns A suitable parameter of type \c query based on \c value.
///
/// @see query.h
ORDO_PUBLIC
size_t block_mode_query(const struct BLOCK_MODE *mode,
                        const struct BLOCK_CIPHER *cipher,
                        int query, size_t value);

//===----------------------------------------------------------------------===//

#ifdef __cplusplus
}
#endif

#endif
