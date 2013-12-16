#ifndef ORDO_ECB_MODE_H
#define ORDO_ECB_MODE_H

#include "ordo/internal/api.h"

#include "ordo/enc/block_modes/mode_params.h"
#include "ordo/primitives/block_ciphers.h"

/******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * @file ecb.h
 * @brief ECB block mode of operation.
 *
 * The ECB mode divides the input message into blocks of the cipher's block
 * size, and encrypts them individually and independently. If the input
 * message's length is not a multiple of the cipher's block size, a padding
 * mechanism is enabled by default which will pad the message to the correct
 * length (and remove the extra data upon decryption). Padding may be disabled
 * via \c ECB_PARAMS, putting constraints on the input message.
 *
 * The ECB mode does not require an initialization vector.
 *
 * Note that the ECB mode is insecure in almost all situations and is not
 * recommended for general purpose use.
*/

struct ECB_STATE;

/*! @see \c block_mode_alloc() */
ORDO_API struct ECB_STATE * ORDO_CALLCONV
ecb_alloc(const struct BLOCK_CIPHER *cipher,
          void *cipher_state);

/*! @see \c block_mode_init() */
ORDO_API int ORDO_CALLCONV
ecb_init(struct ECB_STATE *state,
         const struct BLOCK_CIPHER *cipher,
         void *cipher_state,
         const void *iv, size_t iv_len,
         int dir,
         const struct ECB_PARAMS *params);

/*! @see \c block_mode_update() */
ORDO_API void ORDO_CALLCONV
ecb_update(struct ECB_STATE *state,
           const struct BLOCK_CIPHER *cipher,
           void *cipher_state,
           const unsigned char *in, size_t in_len,
           unsigned char *out, size_t *out_len);

/*! @see \c block_mode_final() */
ORDO_API int ORDO_CALLCONV
ecb_final(struct ECB_STATE *state,
          const struct BLOCK_CIPHER *cipher,
          void *cipher_state,
          unsigned char *out, size_t *out_len);

/*! @see \c block_mode_free() */
ORDO_API void ORDO_CALLCONV
ecb_free(struct ECB_STATE *state,
         const struct BLOCK_CIPHER *cipher,
         void *cipher_state);

/*! @see \c block_mode_copy() */
ORDO_API void ORDO_CALLCONV
ecb_copy(struct ECB_STATE *dst,
         const struct ECB_STATE *src,
         const struct BLOCK_CIPHER *cipher);

/*! @see \c block_mode_query() */
ORDO_API size_t ORDO_CALLCONV
ecb_query(const struct BLOCK_CIPHER *cipher,
          int query, size_t value);

#ifdef __cplusplus
}
#endif

#endif
