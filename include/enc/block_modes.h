#ifndef ORDO_BLOCK_MODES_H
#define ORDO_BLOCK_MODES_H

#include <enc/block_cipher_modes/mode_params.h>
#include <primitives/primitives.h>

/******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * @file block_modes.h
 * @brief Block mode of operation abstraction layer.
 *
 * This abstraction laer declares all the block modes of operation in the
 * library, making them available to higher level modules.
*/

typedef void* (* BLOCK_MODE_ALLOC)(const struct BLOCK_CIPHER *,
                                   void *);

typedef int (* BLOCK_MODE_INIT)(void *, 
                                const struct BLOCK_CIPHER *,
                                void *,
                                const void *,
                                size_t,
                                int,
                                const void *);

typedef void (* BLOCK_MODE_UPDATE)(void *,
                                   const struct BLOCK_CIPHER *,
                                   void *,
                                   const void *,
                                   size_t,
                                   void *,
                                   size_t *);

typedef int (* BLOCK_MODE_FINAL)(void *,
                                 const struct BLOCK_CIPHER *,
                                 void *,
                                 void *,
                                 size_t *);

typedef void (* BLOCK_MODE_FREE)(void *,
                                 const struct BLOCK_CIPHER *,
                                 void *);

typedef void (* BLOCK_MODE_COPY)(void *,
                                 const void *,
                                 const struct BLOCK_CIPHER *);

struct BLOCK_MODE;

void make_block_mode(struct BLOCK_MODE *mode,
                     BLOCK_MODE_ALLOC alloc,
                     BLOCK_MODE_INIT init,
                     BLOCK_MODE_UPDATE update,
                     BLOCK_MODE_FINAL final,
                     BLOCK_MODE_FREE free,
                     BLOCK_MODE_COPY copy,
                     const char *name);

/******************************************************************************/

const char *block_mode_name(const struct BLOCK_MODE *mode);

/******************************************************************************/

/*! Loads all block modes of operation provided by the library.
 @remarks This must be called before you may use \c ECB(), \c CBC(), and so on,
          or functions \c block_mode_by_name(), \c block_mode_by_id(), etc...
*/
void load_block_modes(void);

/*! The ECB (Electronic CodeBook) mode of operation. */
const struct BLOCK_MODE* ECB(void);
/*! The CBC (Ciphertext Block Chaining) mode of operation. */
const struct BLOCK_MODE* CBC(void);
/*! The CTR (CounTeR) mode of operation. */
const struct BLOCK_MODE* CTR(void);
/*! The CFB (Cipher FeedBack) mode of operation. */
const struct BLOCK_MODE* CFB(void);
/*! The OFB (Output FeedBack) mode of operation. */
const struct BLOCK_MODE* OFB(void);

/******************************************************************************/

/*! Gets a block cipher mode of operation from a name. */
const struct BLOCK_MODE* block_mode_by_name(const char* name);

/*! Gets a block cipher mode of operation from an ID. */
const struct BLOCK_MODE* block_mode_by_id(size_t id);

/******************************************************************************/

/*! Allocates a block cipher mode of operation state.
 @param mode A block mode of operation object.
 @param cipher A block cipher object.
 @param cipher_state A block cipher state of type \c cipher.
 @returns Returns an allocated block mode state, or nil on error.
*/
void *block_mode_alloc(const struct BLOCK_MODE* mode,
                       const struct BLOCK_CIPHER *cipher,
                       void *cipher_state);

/*! Initializes a block mode state.
 @param mode A block mode of operation object.
 @param state An allocated block mode state of type \c mode.
 @param cipher A block cipher object.
 @param cipher_state A block cipher state of type \c cipher.
 @param iv The initialization vector to use.
 @param iv_len The length, in bytes, of the initialization vector.
 @param direction Whether to encrypt or decrypt (1 is encryption, 0 decryption)
 @param params Block mode parameters.
 @return Returns #ORDO_SUCCESS on success, or a negative value on error.
*/
int block_mode_init(const struct BLOCK_MODE *mode,
                    void *state,
                    const struct BLOCK_CIPHER *cipher,
                    void *cipher_state,
                    const void *iv,
                    size_t iv_len,
                    int direction,
                    const void *params);

/*! Encrypts or decrypts a buffer.
 @param mode A block mode of operation object.
 @param state An allocated block mode state of type \c mode.
 @param cipher A block cipher object.
 @param cipher_state A block cipher state of type \c cipher.
 @param in The input buffer.
 @param in_len The length, in bytes, of the input buffer.
 @param out The output buffer.
 @param out_len A pointer to an integer in which to write the number of bytes
                that can be returned to the user. Remaining input bytes have
                not been ignored and should not be submitted again.
 @remarks In-place encryption (by letting \c in \c = \c out) may not be
          supported by \c mode, check the relevant documentation.
*/
void block_mode_update(const struct BLOCK_MODE *mode,
                       void *state,
                       const struct BLOCK_CIPHER *cipher,
                       void *cipher_state,
                       const void *in,
                       size_t in_len,
                       void *out,
                       size_t *out_len);

/*! Finalizes a block mode state.
 @param mode A block mode of operation object.
 @param state An allocated block mode state of type \c mode.
 @param cipher A block cipher object.
 @param cipher_state A block cipher state of type \c cipher.
 @param out The output buffer.
 @param out_len A pointer to an integer in which to write the number of bytes
                written to \c out.
 @remarks This function will return any input bytes which were not returned by
          calls to \c block_mode_update().
*/
int block_mode_final(const struct BLOCK_MODE *mode,
                     void *state,
                     const struct BLOCK_CIPHER *cipher,
                     void* cipher_state,
                     void* out,
                     size_t *outlen);

/*! Frees a block mode state.
 @param mode A block mode of operation object.
 @param state An allocated block mode state of type \c mode.
 @param cipher A block cipher object.
 @param cipher_state A block cipher state of type \c cipher.
*/
void block_mode_free(const struct BLOCK_MODE *mode,
                     void *state,
                     const struct BLOCK_CIPHER *cipher,
                     void *cipher_state);

/*! Performs a deep copy of a block mode state into another.
 @param mode A block mode of operation object.
 @param cipher A block cipher object.
 @param dst The destination state.
 @param src The source state.
 @remarks Both states must have been allocated, and, if applicable, initialized
          with the same block cipher, and parameters, or this function triggers
          undefined behaviour.
*/
void block_mode_copy(const struct BLOCK_MODE *mode,
                     const struct BLOCK_CIPHER *cipher,
                     void *dst,
                     const void *src);

#ifdef __cplusplus
}
#endif

#endif
