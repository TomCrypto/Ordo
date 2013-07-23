#ifndef ORDO_NULLCIPHER_H
#define ORDO_NULLCIPHER_H

#include "primitives/block_ciphers/block_params.h"

/******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file nullcipher.h
 *
 * \brief Null Cipher block cipher.
 *
 * This cipher is only used to debug the library and does absolutely nothing,
 * in other words, it is the identity permutation. It accepts no key, that is
 * it only accepts a key length of zero bytes. Its block size is 128 bits and
 * is arbitrarily chosen.
 */

struct NULLCIPHER_STATE;

/*! @see \c block_cipher_alloc() */
struct NULLCIPHER_STATE *nullcipher_alloc(void);

/*! @see \c block_cipher_init()
 *  @retval #ORDO_KEY_LEN if the key length is not zero.
*/
int nullcipher_init(struct NULLCIPHER_STATE *state,
                    const void *key, size_t key_len,
                    const void *params);

/*! @see \c block_cipher_forward() */
void nullcipher_forward(struct NULLCIPHER_STATE *state,
                        void* block);

/*! @see \c block_cipher_inverse() */
void nullcipher_inverse(struct NULLCIPHER_STATE *state,
                        void* block);

/*! @see \c block_cipher_free() */
void nullcipher_free(struct NULLCIPHER_STATE *state);

/*! @see \c block_cipher_copy() */
void nullcipher_copy(struct NULLCIPHER_STATE *dst,
                     const struct NULLCIPHER_STATE *src);

/*! @see \c block_cipher_query() */
size_t nullcipher_query(int query, size_t value);

#ifdef __cplusplus
}
#endif

#endif
