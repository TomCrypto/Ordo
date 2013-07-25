#ifndef ORDO_BLOCK_MODES_H
#define ORDO_BLOCK_MODES_H

#include "enc/block_modes/mode_params.h"
#include "primitives/block_ciphers.h"

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

/*! Returns the name of a block mode object.
 *  @param mode A block mode object.
 *  @returns The name of the block mode object, e.g. "CFB".
 *  @remarks This name can be used in the \c block_mode_by_name() function.
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

size_t block_mode_count(void);

/*! Gets a block mode of operation from a name.
 *  @param name The block mode's name.
 *  @return Returns the relevant block mode object, or nil if no such block
 *          mode was found.
 *  @remarks The \c load_block_modes() function must have been called before,
 *           or this function will fail.
*/
const struct BLOCK_MODE *block_mode_by_name(const char* name);

/*! Gets a block mode of operation from an ID.
 *  @param id The block mode's ID.
 *  @return Returns the relevant block mode object, or nil if no such block
 *          mode was found.
 *  @remarks The \c load_block_modes() function must have been called before,
 *           or this function will fail.
*/
const struct BLOCK_MODE *block_mode_by_id(size_t id);

/******************************************************************************/

/*! Allocates a block cipher mode of operation state.
 *  @param mode A block mode object.
 *  @param cipher A block cipher object.
 *  @param cipher_state A block cipher state of type \c cipher.
 *  @returns Returns an allocated block mode state, or nil on error.
*/
void *block_mode_alloc(const struct BLOCK_MODE *mode,
                       const struct BLOCK_CIPHER *cipher, void *cipher_state);

/*! Initializes a block mode state.
 *  @param mode A block mode object.
 *  @param state An allocated block mode state of type \c mode.
 *  @param cipher A block cipher object.
 *  @param cipher_state A block cipher state of type \c cipher.
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
 *  @param state An allocated block mode state of type \c mode.
 *  @param cipher A block cipher object.
 *  @param cipher_state A block cipher state of type \c cipher.
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
 *  @param state An allocated block mode state of type \c mode.
 *  @param cipher A block cipher object.
 *  @param cipher_state A block cipher state of type \c cipher.
 *  @param out The output buffer.
 *  @param out_len A pointer to an integer to which to write the number of
 *                bytes written to \c out.
 *  @return Returns \c #ORDO_SUCCESS on success, or an error code.
 *  @remarks This function will return any input bytes which were not returned
 *          by calls to \c block_mode_update(), in the correct order.
*/
int block_mode_final(const struct BLOCK_MODE *mode, void *state,
                     const struct BLOCK_CIPHER *cipher, void* cipher_state,
                     void *out, size_t *out_len);

/*! Frees a block mode state.
 *  @param mode A block mode object.
 *  @param state An allocated block mode state of type \c mode.
 *  @param cipher A block cipher object.
 *  @param cipher_state A block cipher state of type \c cipher.
 *  @remarks Once this function has returned, the state can no longer be used
 *           in any \c block_mode_* function, and all information stored in it
 *           will have been erased.
*/
void block_mode_free(const struct BLOCK_MODE *mode, void *state,
                     const struct BLOCK_CIPHER *cipher, void *cipher_state);

/*! Performs a deep copy of a block mode state into another.
 *  @param mode A block mode object.
 *  @param cipher A block cipher object.
 *  @param dst The destination state.
 *  @param src The source state.
 *  @remarks Both \c dst and \c src must have been initialized with the exact
 *           same cipher, cipher parameters, and block mode parameters, else
 *           this function's behavior is undefined.
*/
void block_mode_copy(const struct BLOCK_MODE *mode,
                     const struct BLOCK_CIPHER *cipher,
                     void *dst,
                     const void *src);

/*! Queries a block mode for its supported initialization vector lengths.
 *  @param mode A block mode object.
 *  @param cipher A block cipher object.
 *  @param value A suggested initialization vector length.
 *  @return The smallest valid initialization vector length for this block mode
 *          (using \c cipher) longer than \c iv_len. If no such length exists,
 *          returns the largest supported initialization vector length.
 *  @see query.h
*/
size_t block_mode_query(const struct BLOCK_MODE *mode,
                        const struct BLOCK_CIPHER *cipher,
                        int query, size_t value);

#ifdef __cplusplus
}
#endif

#endif
