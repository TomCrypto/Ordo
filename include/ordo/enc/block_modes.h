#ifndef ORDO_BLOCK_MODES_H
#define ORDO_BLOCK_MODES_H

#include "ordo/enc/block_modes/mode_params.h"
#include "ordo/primitives/block_ciphers.h"

/******************************************************************************/

/*!
 * @file block_modes.h
 * @brief Block cipher mode of operation abstraction layer.
 *
 * This abstraction layer declares all the block modes of operation in the
 * library, making them available to higher level modules.
 *
 * Note "block cipher mode of operation" is shortened to "block mode" in code
 * and documentation to minimize noise and redundancy.
 *
 * The block mode interface follows the usual flow diagram below:
 *
 * @code
 *      +--------------------------------------------------+
 *      |                      +----+                      |
 *      |                      |    |                      |
 *    +-|-----+   +------+   +-v----|-+   +-------+   +----v-+
 *    | alloc |-->| init |-->| update |-->| final |-->| free |
 *    +-------+   +-|----+   +--------+   +-----|-+   +------+
 *                  |                           |
 *                  +---------------------------+
 * @endcode
 *
 * Copying a block mode state - via \c block_mode_copy() - is meaningful only
 * when following \c block_mode_init() and preceding \c block_mode_final().
 *
*/

#ifdef __cplusplus
extern "C" {
#endif

struct BLOCK_MODE;

/******************************************************************************/

/*! Returns the name of a block mode primitive
 *  @param primitive A block mode primitive.
 *  @returns Returns the block mode's name.
 *  @remarks This name can then be used in \c block_mode_by_name().
*/
const char *block_mode_name(const struct BLOCK_MODE *mode);

/******************************************************************************/

/*! The ECB (Electronic CodeBook) block mode of operation. */
const struct BLOCK_MODE *ECB(void);

/*! The CBC (Ciphertext Block Chaining) block mode of operation. */
const struct BLOCK_MODE *CBC(void);

/*! The CTR (CounTeR) block mode of operation. */
const struct BLOCK_MODE *CTR(void);

/*! The CFB (Cipher FeedBack) block mode of operation. */
const struct BLOCK_MODE *CFB(void);

/*! The OFB (Output FeedBack) block mode of operation. */
const struct BLOCK_MODE *OFB(void);

/******************************************************************************/

/*! Returns the number of block modes available.
 *  @returns The number of available block modes (at least one).
 *  @remarks This is for use in enumerating block mode ID's.
*/
size_t block_mode_count(void);

/*! Returns a block mode primitive from a name.
 *  @param name A block mode name.
 *  @returns The corresponding block mode primitive, or nil if no such
 *           block mode exists.
*/
const struct BLOCK_MODE *block_mode_by_name(const char* name);

/*! Returns a block mode primitive from an ID.
 *  @param id A block mode ID.
 *  @returns The corresponding block mode primitive, or nil if no such
 *           block mode exists.
 *  @remarks Use \c block_mode_count() to get an upper bound on
 *           block mode ID's.
*/
const struct BLOCK_MODE *block_mode_by_id(size_t id);

/******************************************************************************/

/*! Allocates a block cipher mode of operation state.
 *  @param mode A block mode object.
 *  @param cipher A block cipher object.
 *  @param cipher_state A block cipher state.
 *  @returns Returns an allocated block mode state, or nil on error.
*/
void *block_mode_alloc(const struct BLOCK_MODE *mode,
                       const struct BLOCK_CIPHER *cipher, void *cipher_state);

/*! Initializes a block mode state.
 *  @param mode A block mode object.
 *  @param state An allocated block mode state.
 *  @param cipher A block cipher object.
 *  @param cipher_state A block cipher state.
 *  @param iv The initialization vector to use.
 *  @param iv_len The length, in bytes, of the initialization vector.
 *  @param direction Whether to encrypt or decrypt.
 *  @param params Block mode parameters.
 *  @return Returns \c #ORDO_SUCCESS on success, or an error code.
 *  @remarks The \c direction parameter is to be set to 0 for decryption, and
 *           1 for encryption.
*/
int block_mode_init(const struct BLOCK_MODE *mode, void *state,
                    const struct BLOCK_CIPHER *cipher, void *cipher_state,
                    const void *iv, size_t iv_len,
                    int direction,
                    const void *params);

/*! Encrypts or decrypts a buffer.
 *  @param mode A block mode object.
 *  @param state An allocated block mode state.
 *  @param cipher A block cipher object.
 *  @param cipher_state A block cipher state.
 *  @param in The input buffer.
 *  @param in_len The length, in bytes, of the input buffer.
 *  @param out The output buffer.
 *  @param out_len A pointer to an integer to which to write the number of
 *                 output bytes that can be returned to the user. Remaining
 *                 input data has \b not been ignored and should not be
 *                 passed again.
 *  @remarks In-place encryption (by letting \c in be the same buffer as
 *           \c out) may not be supported by \c mode, check the relevant
 *           documentation.
*/
void block_mode_update(const struct BLOCK_MODE *mode, void *state,
                       const struct BLOCK_CIPHER *cipher, void *cipher_state,
                       const void *in, size_t in_len,
                       void *out, size_t *out_len);

/*! Finalizes a block mode state.
 *  @param mode A block mode object.
 *  @param state An allocated block mode state.
 *  @param cipher A block cipher object.
 *  @param cipher_state A block cipher state.
 *  @param out The output buffer.
 *  @param out_len A pointer to an integer to which to write the number of
 *                bytes written to \c out.
 *  @return Returns \c #ORDO_SUCCESS on success, or an error code.
 *  @remarks This function will return any input bytes which were not returned
 *           by calls to \c block_mode_update(), in the correct order.
*/
int block_mode_final(const struct BLOCK_MODE *mode, void *state,
                     const struct BLOCK_CIPHER *cipher, void* cipher_state,
                     void *out, size_t *out_len);

/*! Frees a block mode state.
 *  @param mode A block mode primitive.
 *  @param state A block mode state.
 *  @param cipher A block cipher primitive.
 *  @param cipher_state A block cipher state.
*/
void block_mode_free(const struct BLOCK_MODE *mode, void *state,
                     const struct BLOCK_CIPHER *cipher, void *cipher_state);

/*! Copies a block mode state to another.
 *  @param mode A block mode primitive.
 *  @param cipher A block cipher primitive.
 *  @param dst The destination state.
 *  @param src The source state.
 *  @remarks Both states must have been initialized with the same block
 *           mode, block cipher, and parameters (for both).
*/
void block_mode_copy(const struct BLOCK_MODE *mode,
                     const struct BLOCK_CIPHER *cipher,
                     void *dst,
                     const void *src);

/*! Queries a block mode for suitable parameters.
 *  @param mode A block mode primitive.
 *  @param cipher A block cipher primitive.
 *  @param query A query code.
 *  @param value A suggested value.
 *  @returns Returns a suitable parameter of type \c query based on \c value.
 *  @see query.h
*/
size_t block_mode_query(const struct BLOCK_MODE *mode,
                        const struct BLOCK_CIPHER *cipher,
                        int query, size_t value);

#ifdef __cplusplus
}
#endif

#endif
