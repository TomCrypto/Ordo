#ifndef ORDO_CFB_MODE_H
#define ORDO_CFB_MODE_H

#include "ordo/internal/api.h"

#include "ordo/enc/block_modes/mode_params.h"
#include "ordo/primitives/block_ciphers.h"

/******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * @file cfb.h
 * @brief CFB block mode of operation.
 *
 * The CFB mode generates a keystream by repeatedly encrypting an initialization vector and mixing in
 * the plaintext, effectively turning a block cipher into a stream cipher. As such, CFB mode requires no
 * padding, and the ciphertext size will always be equal to the plaintext size.
 *
 * Note that the CFB keystream depends on the plaintext fed into it, as opposed to OFB mode. This also
 * means the block cipher's inverse permutation is never used.
 *
 * \c cfb_final() accepts 0 as an argument for \c outlen, since by design the CFB mode of operation does not
 * produce any final data. However, if a valid pointer is passed, its value will be set to zero as expected.
*/

struct CFB_STATE;

/*! @see \c block_mode_alloc() */
ORDO_API struct CFB_STATE * ORDO_CALLCONV
cfb_alloc(const struct BLOCK_CIPHER *cipher,
          void *cipher_state);

/*! @see \c block_mode_init() */
ORDO_API int ORDO_CALLCONV
cfb_init(struct CFB_STATE *state,
         const struct BLOCK_CIPHER *cipher,
         void *cipher_state,
         const void *iv, size_t iv_len,
         int dir,
         const void *params);

/*! @see \c block_mode_update() */
ORDO_API void ORDO_CALLCONV
cfb_update(struct CFB_STATE *state,
           const struct BLOCK_CIPHER *cipher,
           void *cipher_state,
           const unsigned char *in, size_t in_len,
           unsigned char *out, size_t *out_len);

/*! @see \c block_mode_final() */
ORDO_API int ORDO_CALLCONV
cfb_final(struct CFB_STATE *state,
          const struct BLOCK_CIPHER *cipher,
          void *cipher_state,
          unsigned char *out, size_t *out_len);

/*! @see \c block_mode_free() */
ORDO_API void ORDO_CALLCONV
cfb_free(struct CFB_STATE *state,
         const struct BLOCK_CIPHER *cipher,
         void *cipher_state);

/*! @see \c block_mode_copy() */
ORDO_API void ORDO_CALLCONV
cfb_copy(struct CFB_STATE *dst,
         const struct CFB_STATE *src,
         const struct BLOCK_CIPHER *cipher);

/*! @see \c block_mode_query() */
ORDO_API size_t ORDO_CALLCONV
cfb_query(const struct BLOCK_CIPHER *cipher,
          int query, size_t value);

#ifdef __cplusplus
}
#endif

#endif
