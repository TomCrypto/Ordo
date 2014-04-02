/*===-- primitives/block_ciphers/threefish256.h --------*- PUBLIC -*- H -*-===*/
/**
/// @file
/// @brief Primitive
///
/// Threefish-256 is  a block cipher with  a 256-bit block size  and a 256-bit
/// key size. It also has an optional  128-bit tweak, which can be set through
/// the cipher parameters.
///
/// The Threefish  ciphers were originally designed  to be used as  a building
/// block for the Skein hash function family.
**/
/*===----------------------------------------------------------------------===*/

#ifndef ORDO_THREEFISH256_H
#define ORDO_THREEFISH256_H

/** @cond **/
#include "ordo/common/interface.h"
/** @endcond **/

#include "ordo/primitives/block_ciphers/block_params.h"

#ifdef __cplusplus
extern "C" {
#endif

/*===----------------------------------------------------------------------===*/

struct THREEFISH256_STATE;

/** @see \c block_cipher_alloc()
**/
ORDO_PUBLIC
struct THREEFISH256_STATE *threefish256_alloc(void);

/** @see \c block_cipher_init()
///
/// @retval #ORDO_KEY_LEN if the key length is not 32 (bytes).
**/
ORDO_PUBLIC
int threefish256_init(struct THREEFISH256_STATE *state,
                      const uint64_t *key, size_t key_len,
                      const struct THREEFISH256_PARAMS *params);

/** @see \c block_cipher_forward()
**/
ORDO_PUBLIC
void threefish256_forward(const struct THREEFISH256_STATE *state,
                          uint64_t *block);

/** @see \c block_cipher_inverse()
**/
ORDO_PUBLIC
void threefish256_inverse(const struct THREEFISH256_STATE *state,
                          uint64_t *block);

/** @see \c block_cipher_final()
**/
ORDO_PUBLIC
void threefish256_final(struct THREEFISH256_STATE *state);

/** @see \c block_cipher_free()
**/
ORDO_PUBLIC
void threefish256_free(struct THREEFISH256_STATE *state);

/** @see \c block_cipher_copy()
**/
ORDO_PUBLIC
void threefish256_copy(struct THREEFISH256_STATE *dst,
                       const struct THREEFISH256_STATE *src);

/** @see \c block_cipher_query()
**/
ORDO_PUBLIC
size_t threefish256_query(int query, size_t value);

/*===----------------------------------------------------------------------===*/

#ifdef __cplusplus
}
#endif

#endif
