#ifndef ORDO_RC4_H
#define ORDO_RC4_H

#include "primitives/stream_ciphers/stream_params.h"

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

/*! @see \c enc_stream_alloc() */
struct RC4_STATE *rc4_alloc(void);

/*! @see \c enc_stream_init()
 *  @retval #ORDO_KEY_LEN if the key length was less than 40 bits (5 bytes) or
 *                        more than 2048 bits (256 bytes).
 *  @remarks The number of keystream bytes to drop can be set via the \c params
 *           argument, see \c RC4_PARAMS. By default, 2048 bytes are dropped.
*/
int rc4_init(struct RC4_STATE *state,
             const uint8_t *key, size_t key_len,
             const struct RC4_PARAMS *params);

/*! @see \c enc_stream_update() */
void rc4_update(struct RC4_STATE *state,
                uint8_t *buffer, size_t len);

/*! @see \c enc_stream_free() */
void rc4_free(struct RC4_STATE *state);

/*! @see \c enc_stream_copy() */
void rc4_copy(struct RC4_STATE *dst,
              const struct RC4_STATE *src);

/*! Probes the RC4 stream cipher for its key length.
 @param key_len The suggested key length.
 @returns As RC4 supports keys between 40 and 2048 bits (5 and 256 bytes),
          this function will return \c key_len if it is within this interval,
          will return 5 if it is lower, and 256 if it is larger.
*/

/*! @see \c enc_stream_key_len
    @returns As RC4 supports keys between 40 and 2048 bits (5 and 256 bytes),
             this function will return \c key_len if it is within this
             interval, will return 5 if it is lower, and 256 if it is larger.
*/
size_t rc4_query(int query, size_t value);

#ifdef __cplusplus
}
#endif

#endif
