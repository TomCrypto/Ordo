/*===-- primitives/block_ciphers/nullcipher.h ----------*- PUBLIC -*- H -*-===*/
/**
/// @file
/// @brief Primitive
///
/// This cipher is only used to debug the library and does absolutely nothing,
/// in other words, it is the identity permutation. It accepts no key, that is
/// it only accepts a key length of zero bytes. Its block size is 128 bits and
/// is arbitrarily chosen.
**/
/*===----------------------------------------------------------------------===*/

#ifndef ORDO_NULLCIPHER_H
#define ORDO_NULLCIPHER_H

/** @cond **/
#include "ordo/common/interface.h"
/** @endcond **/

#include "ordo/primitives/block_ciphers/block_params.h"

#ifdef __cplusplus
extern "C" {
#endif

/*===----------------------------------------------------------------------===*/

/** @see \c block_cipher_init()
///
/// @retval #ORDO_KEY_LEN if the key length is not zero.
**/
ORDO_PUBLIC
int nullcipher_init(struct NULLCIPHER_STATE *state,
                    const void *key, size_t key_len,
                    const void *params);

/** @see \c block_cipher_forward()
**/
ORDO_PUBLIC
void nullcipher_forward(const struct NULLCIPHER_STATE *state,
                        void *block);

/** @see \c block_cipher_inverse()
**/
ORDO_PUBLIC
void nullcipher_inverse(const struct NULLCIPHER_STATE *state,
                        void *block);

/** @see \c block_cipher_final()
**/
ORDO_PUBLIC
void nullcipher_final(struct NULLCIPHER_STATE *state);

/** @see \c block_cipher_query()
**/
ORDO_PUBLIC
size_t nullcipher_query(int query, size_t value);

/*===----------------------------------------------------------------------===*/

#ifdef __cplusplus
}
#endif

#endif
