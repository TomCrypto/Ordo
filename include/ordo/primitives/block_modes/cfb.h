/*===-- enc/block_modes/cfb.h --------------------------*- PUBLIC -*- H -*-===*/
/**
*** @file
*** @brief Primitive
***
*** The  CFB   mode  generates  a   keystream  by  repeatedly   encrypting  an
*** initialization vector and  mixing in the plaintext,  effectively turning a
*** block cipher into a stream cipher.  As such, CFB mode requires no padding,
*** and the ciphertext size will always be equal to the plaintext size.
***
*** Note  that  the CFB  keystream  depends  on  the  plaintext fed  into  it,
*** as  opposed to  OFB  mode.  This also  means  the  block cipher's  inverse
*** permutation is never used.
***
*** \c cfb_final() accepts 0 as an argument for \c out_len since by design the
*** CFB mode of operation does not produce any final data. However, if a valid
*** pointer is passed, its value will be set to zero as expected.
**/
/*===----------------------------------------------------------------------===*/

#ifndef ORDO_CFB_MODE_H
#define ORDO_CFB_MODE_H

/** @cond **/
#include "ordo/common/interface.h"
/** @endcond **/

#include "ordo/primitives/block_modes/mode_params.h"
#include "ordo/primitives/block_ciphers.h"

#ifdef __cplusplus
extern "C" {
#endif

/*===----------------------------------------------------------------------===*/

#define cfb_init                         ordo_cfb_init
#define cfb_update                       ordo_cfb_update
#define cfb_final                        ordo_cfb_final
#define cfb_query                        ordo_cfb_query
#define cfb_bsize                        ordo_cfb_bsize

/*===----------------------------------------------------------------------===*/

/** @see \c block_mode_init()
**/
ORDO_PUBLIC
int cfb_init(struct CFB_STATE *state,
             struct BLOCK_STATE *cipher_state,
             const void *iv, size_t iv_len,
             int dir,
             const void *params);

/** @see \c block_mode_update()
**/
ORDO_PUBLIC
void cfb_update(struct CFB_STATE *state,
                struct BLOCK_STATE *cipher_state,
                const unsigned char *in, size_t in_len,
                unsigned char *out, size_t *out_len);

/** @see \c block_mode_final()
**/
ORDO_PUBLIC
int cfb_final(struct CFB_STATE *state,
              struct BLOCK_STATE *cipher_state,
              unsigned char *out, size_t *out_len);

/** @see \c block_mode_query()
**/
ORDO_PUBLIC
size_t cfb_query(prim_t cipher,
                 int query, size_t value);

/** Gets the size in bytes of a \c CFB_STATE.
***
*** @returns The size in bytes of the structure.
***
*** @remarks Binary compatibility layer.
**/
ORDO_PUBLIC
size_t cfb_bsize(void);

/*===----------------------------------------------------------------------===*/

#ifdef __cplusplus
}
#endif

#endif
