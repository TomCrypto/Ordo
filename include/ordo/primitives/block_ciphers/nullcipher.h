/*===-- primitives/block_ciphers/nullcipher.h ----------*- PUBLIC -*- H -*-===*/
/**
*** @file
*** @brief Primitive
***
*** This cipher is only used to debug the library and does absolutely nothing,
*** in other words, it is the identity permutation. It accepts no key, that is
*** it only accepts a key length of zero bytes. Its block size is 128 bits and
*** is arbitrarily chosen.
**/
/*===----------------------------------------------------------------------===*/

#ifndef ORDO_NULLCIPHER_H
#define ORDO_NULLCIPHER_H

/** @cond **/
#include "ordo/common/interface.h"
/** @endcond **/

#include "ordo/primitives/block_ciphers.h"

#ifdef __cplusplus
extern "C" {
#endif

/*===----------------------------------------------------------------------===*/

#define nullcipher_init                  ordo_nullcipher_init
#define nullcipher_forward               ordo_nullcipher_forward
#define nullcipher_inverse               ordo_nullcipher_inverse
#define nullcipher_final                 ordo_nullcipher_final
#define nullcipher_limits                ordo_nullcipher_limits
#define nullcipher_bsize                 ordo_nullcipher_bsize

/*===----------------------------------------------------------------------===*/

/** @see \c block_init()
***
*** @retval #ORDO_KEY_LEN if the key length is not zero.
**/
ORDO_PUBLIC
int nullcipher_init(struct NULLCIPHER_STATE *state,
                    const void *key, size_t key_len,
                    const void *params);

/** @see \c block_forward()
**/
ORDO_PUBLIC
void nullcipher_forward(const struct NULLCIPHER_STATE *state,
                        void *block);

/** @see \c block_inverse()
**/
ORDO_PUBLIC
void nullcipher_inverse(const struct NULLCIPHER_STATE *state,
                        void *block);

/** @see \c block_final()
**/
ORDO_PUBLIC
void nullcipher_final(struct NULLCIPHER_STATE *state);

/** @see \c block_limits()
**/
ORDO_PUBLIC
int nullcipher_limits(struct BLOCK_LIMITS *limits);

/** Gets the size in bytes of a \c NULLCIPHER_STATE.
***
*** @returns The size in bytes of the structure.
***
*** @remarks Binary compatibility layer.
**/
ORDO_PUBLIC
size_t nullcipher_bsize(void);

/*===----------------------------------------------------------------------===*/

#ifdef __cplusplus
}
#endif

#endif
