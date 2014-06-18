/*===-- primitives/block_ciphers/aes.h -----------------*- PUBLIC -*- H -*-===*/
/**
*** @file
*** @brief Primitive
***
*** AES (Advanced  Encryption Standard) is  a block  cipher. It has  a 128-bit
*** block size and three possible key sizes,  namely 128, 192 and 256 bits. It
*** is  based  on  the  Rijndael  cipher and  was  selected  as  the  official
*** encryption standard on November 2001 (FIPS 197).
**/
/*===----------------------------------------------------------------------===*/

#ifndef ORDO_AES_H
#define ORDO_AES_H

/** @cond **/
#include "ordo/common/interface.h"
/** @endcond **/

#include "ordo/primitives/block_ciphers/block_params.h"

#ifdef __cplusplus
extern "C" {
#endif

/*===----------------------------------------------------------------------===*/

#define aes_init                         ordo_aes_init
#define aes_forward                      ordo_aes_forward
#define aes_inverse                      ordo_aes_inverse
#define aes_final                        ordo_aes_final
#define aes_query                        ordo_aes_query

/*===----------------------------------------------------------------------===*/

/** @see \c block_init()
***
*** @retval #ORDO_KEY_LEN if the key length is not 16, 24, or 32 (bytes).
*** @retval #ORDO_ARG if parameters were provided and requested zero rounds or
***                   more than 20 rounds.
**/
ORDO_PUBLIC
int aes_init(struct AES_STATE *state,
             const void *key, size_t key_len,
             const struct AES_PARAMS *params);

/** @see \c block_forward()
**/
ORDO_PUBLIC
void aes_forward(const struct AES_STATE *state,
                 uint8_t *block);

/** @see \c block_inverse()
**/
ORDO_PUBLIC
void aes_inverse(const struct AES_STATE *state,
                 uint8_t *block);

/** @see \c block_final()
**/
ORDO_PUBLIC
void aes_final(struct AES_STATE *state);

/** @see \c block_query()
**/
ORDO_PUBLIC
size_t aes_query(int query, size_t value);

/*===----------------------------------------------------------------------===*/

#ifdef __cplusplus
}
#endif

#endif
