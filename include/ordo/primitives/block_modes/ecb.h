/*===-- enc/block_modes/ecb.h --------------------------*- PUBLIC -*- H -*-===*/
/**
*** @file
*** @brief Primitive
***
*** The ECB mode  divides the input message into blocks  of the cipher's block
*** size,  and encrypts  them  individually and  independently.  If the  input
*** message's length is  not a multiple of the cipher's  block size, a padding
*** mechanism is enabled by default which  will pad the message to the correct
*** length  (and  remove the  extra  data  upon  decryption). Padding  may  be
*** disabled via \c ECB_PARAMS, putting constraints on the input message.
***
*** The ECB mode does not require an initialization vector.
***
*** Note that  the ECB mode  is insecure in almost  all situations and  is not
*** recommended for general purpose use.
**/
/*===----------------------------------------------------------------------===*/

#ifndef ORDO_ECB_MODE_H
#define ORDO_ECB_MODE_H

/** @cond **/
#include "ordo/common/interface.h"
/** @endcond **/

#include "ordo/primitives/block_modes.h"

#ifdef __cplusplus
extern "C" {
#endif

/*===----------------------------------------------------------------------===*/

#define ecb_init                         ordo_ecb_init
#define ecb_update                       ordo_ecb_update
#define ecb_final                        ordo_ecb_final
#define ecb_query                        ordo_ecb_query
#define ecb_bsize                        ordo_ecb_bsize

/*===----------------------------------------------------------------------===*/

/** @see \c block_mode_init()
**/
ORDO_PUBLIC
int ecb_init(struct ECB_STATE *state,
             struct BLOCK_STATE *cipher_state,
             const void *iv, size_t iv_len,
             int dir,
             const struct ECB_PARAMS *params);

/** @see \c block_mode_update()
**/
ORDO_PUBLIC
void ecb_update(struct ECB_STATE *state,
                struct BLOCK_STATE *cipher_state,
                const void *in, size_t in_len,
                void *out, size_t *out_len);

/** @see \c block_mode_final()
**/
ORDO_PUBLIC
int ecb_final(struct ECB_STATE *state,
              struct BLOCK_STATE *cipher_state,
              void *out, size_t *out_len);

/** @see \c block_mode_query()
**/
ORDO_PUBLIC
size_t ecb_query(prim_t cipher,
                 int query, size_t value);

/** Gets the size in bytes of a \c ECB_STATE.
***
*** @returns The size in bytes of the structure.
***
*** @remarks Binary compatibility layer.
**/
ORDO_PUBLIC
size_t ecb_bsize(void);

/*===----------------------------------------------------------------------===*/

#ifdef __cplusplus
}
#endif

#endif
