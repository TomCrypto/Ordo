#ifndef ORDO_AES_H
#define ORDO_AES_H

#include "ordo/internal/api.h"

#include "ordo/primitives/block_ciphers/block_params.h"

/******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file aes.h
 *
 * \brief AES block cipher.
 *
 * AES (Advanced Encryption Standard) is a block cipher. It has a 128-bit block
 * size and three possible key sizes, namely 128, 192 and 256 bits. It is based
 * on the Rijndael cipher and was selected as the official encryption standard
 * on November 2001 (FIPS 197).
 */

struct AES_STATE;

/*! @see \c block_cipher_alloc() */
ORDO_API struct AES_STATE * ORDO_CALLCONV
aes_alloc(void);

/*! @see \c block_cipher_init()
 *  @retval #ORDO_KEY_LEN if the key length is not 16, 24, or 32 (bytes).
 *  @retval #ORDO_ARG if parameters were provided and requested zero rounds
 *                    or more than 20 rounds.
*/
ORDO_API int ORDO_CALLCONV
aes_init(struct AES_STATE *state,
         const void *key, size_t key_len,
         const struct AES_PARAMS *params);

/*! @see \c block_cipher_forward() */
ORDO_API void ORDO_CALLCONV
aes_forward(struct AES_STATE *state,
            uint8_t *block);

/*! @see \c block_cipher_inverse() */
ORDO_API void ORDO_CALLCONV
aes_inverse(struct AES_STATE *state,
            uint8_t *block);

/*! @see \c block_cipher_free() */
ORDO_API void ORDO_CALLCONV
aes_free(struct AES_STATE *state);

/*! @see \c block_cipher_copy() */
ORDO_API void ORDO_CALLCONV
aes_copy(struct AES_STATE *dst,
         const struct AES_STATE *src);

/*! @see \c block_cipher_query() */
ORDO_API size_t ORDO_CALLCONV
aes_query(int query, size_t value);

#ifdef __cplusplus
}
#endif

#endif
