#ifndef ORDO_CBC_MODE_H
#define ORDO_CBC_MODE_H

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
struct CBC_STATE *cbc_alloc(const struct BLOCK_CIPHER *cipher,
                            void *cipher_state);

/*! @see \c block_mode_init() */
int cbc_init(struct CBC_STATE *state,
             const struct BLOCK_CIPHER *cipher,
             void *cipher_state,
             const void *iv, size_t iv_len,
             int dir,
             const struct CBC_PARAMS *params);

/*! @see \c block_mode_update() */
void cbc_update(struct CBC_STATE *state,
                const struct BLOCK_CIPHER *cipher,
                void *cipher_state,
                const unsigned char *in, size_t in_len,
                unsigned char *out, size_t *out_len);

/*! @see \c block_mode_final() */
int cbc_final(struct CBC_STATE *state,
              const struct BLOCK_CIPHER *cipher,
              void *cipher_state,
              unsigned char *out, size_t *out_len);

/*! @see \c block_mode_free() */
void cbc_free(struct CBC_STATE *state,
              const struct BLOCK_CIPHER *cipher,
              void *cipher_state);

/*! @see \c block_mode_copy() */
void cbc_copy(struct CBC_STATE *dst,
              const struct CBC_STATE *src,
              const struct BLOCK_CIPHER *cipher);

/*! @see \c block_mode_query() */
size_t cbc_query(const struct BLOCK_CIPHER *cipher,
                 int query, size_t value);

#ifdef __cplusplus
}
#endif

#endif