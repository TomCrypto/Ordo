#ifndef ORDO_CBC_MODE_H
#define ORDO_CBC_MODE_H

#include "ordo/internal/api.h"

#include "ordo/enc/block_modes/mode_params.h"
#include "ordo/primitives/block_ciphers.h"

/******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * @file cbc.h
 * @brief CBC block mode of operation.
 *
 * The CBC mode divides the input message into blocks of the cipher's block size, and encrypts them in a sequential
 * fashion, where each block depends on the previous one (and the first block depends on the initialization vector).
 * If the input message's length is not a multiple of the cipher's block size, a padding mechanism is enabled by
 * default which will pad the message to the correct length (and remove the extra data upon decryption). If
 * padding is explicitly disabled through the mode of operation's parameters, the input's length must be a multiple
 * of the cipher's block size.
 *
 * If padding is enabled, \c cbc_final() requires a valid pointer to be passed in the \c outlen parameter and will
 * always return a full blocksize of data, containing the last few ciphertext bytes containing the padding information.
 *
 * If padding is disabled, \c outlen is also required, and will return the number of unprocessed plaintext bytes in the
 * context. If this is any value other than zero, the function will also fail with \c ORDO_LEFTOVER.
*/

struct CBC_STATE;

/*! @see \c block_mode_alloc() */
ORDO_API struct CBC_STATE * ORDO_CALLCONV
cbc_alloc(const struct BLOCK_CIPHER *cipher,
          void *cipher_state);

/*! @see \c block_mode_init() */
ORDO_API int ORDO_CALLCONV
cbc_init(struct CBC_STATE *state,
         const struct BLOCK_CIPHER *cipher,
         void *cipher_state,
         const void *iv, size_t iv_len,
         int dir,
         const struct CBC_PARAMS *params);

/*! @see \c block_mode_update() */
ORDO_API void ORDO_CALLCONV
cbc_update(struct CBC_STATE *state,
           const struct BLOCK_CIPHER *cipher,
           void *cipher_state,
           const unsigned char *in, size_t in_len,
           unsigned char *out, size_t *out_len);

/*! @see \c block_mode_final() */
ORDO_API int ORDO_CALLCONV
cbc_final(struct CBC_STATE *state,
          const struct BLOCK_CIPHER *cipher,
          void *cipher_state,
          unsigned char *out, size_t *out_len);

/*! @see \c block_mode_free() */
ORDO_API void ORDO_CALLCONV
cbc_free(struct CBC_STATE *state,
         const struct BLOCK_CIPHER *cipher,
         void *cipher_state);

/*! @see \c block_mode_copy() */
ORDO_API void ORDO_CALLCONV
cbc_copy(struct CBC_STATE *dst,
         const struct CBC_STATE *src,
         const struct BLOCK_CIPHER *cipher);

/*! @see \c block_mode_query() */
ORDO_API size_t ORDO_CALLCONV
cbc_query(const struct BLOCK_CIPHER *cipher,
          int query, size_t value);

#ifdef __cplusplus
}
#endif

#endif
