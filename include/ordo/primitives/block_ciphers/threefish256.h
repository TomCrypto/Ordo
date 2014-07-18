/*===-- primitives/block_ciphers/threefish256.h --------*- PUBLIC -*- H -*-===*/
/**
*** @file
*** @brief Primitive
***
*** Threefish-256 is  a block cipher with  a 256-bit block size  and a 256-bit
*** key size. It also has an optional  128-bit tweak, which can be set through
*** the cipher parameters.
***
*** The Threefish  ciphers were originally designed  to be used as  a building
*** block for the Skein hash function family.
**/
/*===----------------------------------------------------------------------===*/

#ifndef ORDO_THREEFISH256_H
#define ORDO_THREEFISH256_H

/** @cond **/
#include "ordo/common/interface.h"
/** @endcond **/

#include "ordo/primitives/block_ciphers.h"

#ifdef __cplusplus
extern "C" {
#endif

/*===----------------------------------------------------------------------===*/

#define threefish256_init                ordo_threefish256_init
#define threefish256_forward             ordo_threefish256_forward
#define threefish256_inverse             ordo_threefish256_inverse
#define threefish256_final               ordo_threefish256_final
#define threefish256_query               ordo_threefish256_query
#define threefish256_bsize               ordo_threefish256_bsize

/*===----------------------------------------------------------------------===*/

/** @see \c block_init()
***
*** @retval #ORDO_KEY_LEN if the key length is not 32 (bytes).
**/
ORDO_PUBLIC
int threefish256_init(struct THREEFISH256_STATE *state,
                      const void *key, size_t key_len,
                      const struct THREEFISH256_PARAMS *params);

/** @see \c block_forward()
**/
ORDO_PUBLIC
void threefish256_forward(const struct THREEFISH256_STATE *state,
                          void *block);

/** @see \c block_inverse()
**/
ORDO_PUBLIC
void threefish256_inverse(const struct THREEFISH256_STATE *state,
                          void *block);

/** @see \c block_final()
**/
ORDO_PUBLIC
void threefish256_final(struct THREEFISH256_STATE *state);

/** @see \c block_query()
**/
ORDO_PUBLIC
size_t threefish256_query(int query, size_t value);

/** Gets the size in bytes of a \c THREEFISH256_STATE.
***
*** @returns The size in bytes of the structure.
***
*** @remarks Binary compatibility layer.
**/
ORDO_PUBLIC
size_t threefish256_bsize(void);

/*===----------------------------------------------------------------------===*/

#ifdef __cplusplus
}
#endif

#endif
