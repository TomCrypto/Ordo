#ifndef ORDO_RC4_H
#define ORDO_RC4_H

#include "ordo/internal/api.h"

#include "ordo/primitives/stream_ciphers/stream_params.h"

/******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * @file rc4.h
 * @brief RC4 stream cipher.
 *
 * RC4 is a stream cipher, which accepts keys between 40 and 2048 bits (in
 * multiples of 8 bits only). It accepts a parameter consisting of the number
 * of initial keystream bytes to drop immediately after key schedule,
 * effectively implementing RC4-drop[n]. If no drop parameter is passed,
 * the implementation drops 2048 bytes by default.
 *
 * @todo Better ABI translation for Windows assembler implementation(right now
 * it's a brute-force push/pop/swap to explicitly translate parameter passing)
*/

struct RC4_STATE;

/*! @see \c stream_cipher_alloc() */
ORDO_API struct RC4_STATE * ORDO_CALLCONV
rc4_alloc(void);

/*! @see \c stream_cipher_init()
 *  @retval #ORDO_KEY_LEN if the key length was less than 40 bits (5 bytes) or
 *                        more than 2048 bits (256 bytes).
 *  @remarks The number of keystream bytes to drop can be set via the \c params
 *           argument, see \c RC4_PARAMS. By default, 2048 bytes are dropped.
*/
ORDO_API int ORDO_CALLCONV
rc4_init(struct RC4_STATE *state,
         const uint8_t *key, size_t key_len,
         const struct RC4_PARAMS *params);

/*! @see \c stream_cipher_update() */
ORDO_API void ORDO_CALLCONV
rc4_update(struct RC4_STATE *state,
           uint8_t *buffer, size_t len);

/*! @see \c stream_cipher_free() */
ORDO_API void ORDO_CALLCONV
rc4_free(struct RC4_STATE *state);

/*! @see \c stream_cipher_copy() */
ORDO_API void ORDO_CALLCONV
rc4_copy(struct RC4_STATE *dst,
         const struct RC4_STATE *src);

/*! @see \c stream_cipher_query() */
ORDO_API size_t ORDO_CALLCONV
rc4_query(int query, size_t value);

#ifdef __cplusplus
}
#endif

#endif
