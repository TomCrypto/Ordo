#ifndef ORDO_OFB_MODE_H
#define ORDO_OFB_MODE_H

#include "ordo/enc/block_modes/mode_params.h"
#include "ordo/primitives/block_ciphers.h"

/******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * @file ofb.h
 * @brief OFB block mode of operation.
 *
 * The OFB mode generates a keystream by repeatedly encrypting an initialization vector, effectively
 * turning a block cipher into a stream cipher. As such, OFB mode requires no padding, and outlen
 * will always be equal to inlen.
 *
 * Note that the OFB keystream is independent of the plaintext, so a key/iv pair must never be
 * used for more than one message. This also means the block cipher's inverse permutation is
 * never used.
 *
 * \c ofb_final() accepts 0 as an argument for \c outlen, since by design the OFB mode of operation does not
 * produce any final data. However, if a valid pointer is passed, its value will be set to zero as expected.
*/

struct OFB_STATE;

/*! @see \c block_mode_alloc() */
struct OFB_STATE *ofb_alloc(const struct BLOCK_CIPHER *cipher,
                            void *cipher_state);

/*! @see \c block_mode_init() */
int ofb_init(struct OFB_STATE *state,
             const struct BLOCK_CIPHER *cipher,
             void *cipher_state,
             const void *iv, size_t iv_len,
             int dir,
             const void *params);

/*! @see \c block_mode_update() */
void ofb_update(struct OFB_STATE *state,
                const struct BLOCK_CIPHER *cipher,
                void *cipher_state,
                const unsigned char *in, size_t in_len,
                unsigned char *out, size_t *out_len);

/*! @see \c block_mode_final() */
int ofb_final(struct OFB_STATE *state,
              const struct BLOCK_CIPHER *cipher,
              void *cipher_state,
              unsigned char *out, size_t *out_len);

/*! @see \c block_mode_free() */
void ofb_free(struct OFB_STATE *state,
              const struct BLOCK_CIPHER *cipher,
              void *cipher_state);

/*! @see \c block_mode_copy() */
void ofb_copy(struct OFB_STATE *dst,
              const struct OFB_STATE *src,
              const struct BLOCK_CIPHER *cipher);

/*! @see \c block_mode_query() */
size_t ofb_query(const struct BLOCK_CIPHER *cipher,
                 int query, size_t value);

#ifdef __cplusplus
}
#endif

#endif
