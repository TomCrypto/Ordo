/*===-- enc/block_modes/ctr.h --------------------------*- PUBLIC -*- H -*-===*/
/**
*** @file
*** @brief Primitive
***
*** The  CTR mode  generates a  keystream by  repeatedly encrypting  a counter
*** starting  from some  initialization  vector, effectively  turning a  block
*** cipher into  a stream cipher. As  such, CTR mode requires  no padding, and
*** outlen will always be equal to inlen.
***
*** Note that the  CTR keystream is independent of the  plaintext, and is also
*** spatially  coherent (using  a given  initialization vector  on a  len-byte
*** message will "use up" len bytes of the keystream) so care must be taken to
*** avoid  reusing the  initialization vector  in an  insecure way.  This also
*** means the block cipher's inverse permutation is never used.
***
*** \c ctr_final() accepts 0 as an argument for \c out_len since by design the
*** CTR mode of operation does not produce any final data. However, if a valid
*** pointer is passed, its value will be set to zero as expected.
**/
/*===----------------------------------------------------------------------===*/

#ifndef ORDO_CTR_MODE_H
#define ORDO_CTR_MODE_H

/** @cond **/
#include "ordo/common/interface.h"
/** @endcond **/

#include "ordo/primitives/block_modes/mode_params.h"
#include "ordo/primitives/block_ciphers.h"

#ifdef __cplusplus
extern "C" {
#endif

/*===----------------------------------------------------------------------===*/

#define ctr_init                         ordo_ctr_init
#define ctr_update                       ordo_ctr_update
#define ctr_final                        ordo_ctr_final
#define ctr_query                        ordo_ctr_query
#define ctr_bsize                        ordo_ctr_bsize

/*===----------------------------------------------------------------------===*/

/** @see \c block_mode_init()
**/
ORDO_PUBLIC
int ctr_init(struct CTR_STATE *state,
             struct BLOCK_STATE *cipher_state,
             const void *iv, size_t iv_len,
             int dir,
             const void *params);

/** @see \c block_mode_update()
**/
ORDO_PUBLIC
void ctr_update(struct CTR_STATE *state,
                struct BLOCK_STATE *cipher_state,
                const unsigned char *in, size_t in_len,
                unsigned char *out, size_t *out_len);

/** @see \c block_mode_final()
**/
ORDO_PUBLIC
int ctr_final(struct CTR_STATE *state,
              struct BLOCK_STATE *cipher_state,
              unsigned char *out, size_t *out_len);

/** @see \c block_mode_query()
**/
ORDO_PUBLIC
size_t ctr_query(prim_t cipher,
                 int query, size_t value);

/** Gets the size in bytes of a \c CTR_STATE.
***
*** @returns The size in bytes of the structure.
***
*** @remarks Binary compatibility layer.
**/
ORDO_PUBLIC
size_t ctr_bsize(void);

/*===----------------------------------------------------------------------===*/

#ifdef __cplusplus
}
#endif

#endif
