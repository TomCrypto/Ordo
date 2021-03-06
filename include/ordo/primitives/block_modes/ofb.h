/*===-- enc/block_modes/ofb.h --------------------------*- PUBLIC -*- H -*-===*/
/**
*** @file
*** @brief Primitive
***
*** The  OFB   mode  generates  a   keystream  by  repeatedly   encrypting  an
*** initialization vector,  effectively turning a  block cipher into  a stream
*** cipher. As such,  OFB mode requires no padding, and  outlen will always be
*** equal to inlen.
***
*** Note that the  OFB keystream is independent of the  plaintext, so a key/iv
*** pair must  never be used  for more than one  message. This also  means the
*** block cipher's inverse permutation is never used.
***
*** \c ofb_final() accepts 0 as an argument for \c out_len since by design the
*** OFB mode of operation does not produce any final data. However, if a valid
*** pointer is passed, its value will be set to zero as expected.
**/
/*===----------------------------------------------------------------------===*/

#ifndef ORDO_OFB_MODE_H
#define ORDO_OFB_MODE_H

/** @cond **/
#include "ordo/common/interface.h"
/** @endcond **/

#include "ordo/primitives/block_modes.h"

#ifdef __cplusplus
extern "C" {
#endif

/*===----------------------------------------------------------------------===*/

#define ofb_init                         ordo_ofb_init
#define ofb_update                       ordo_ofb_update
#define ofb_final                        ordo_ofb_final
#define ofb_limits                       ordo_ofb_limits
#define ofb_bsize                        ordo_ofb_bsize

/*===----------------------------------------------------------------------===*/

/** @see \c block_mode_init()
**/
ORDO_PUBLIC
int ofb_init(struct OFB_STATE *state,
             struct BLOCK_STATE *cipher_state,
             const void *iv, size_t iv_len,
             int dir,
             const void *params);

/** @see \c block_mode_update()
**/
ORDO_PUBLIC
void ofb_update(struct OFB_STATE *state,
                struct BLOCK_STATE *cipher_state,
                const void *in, size_t in_len,
                void *out, size_t *out_len);

/** @see \c block_mode_final()
**/
ORDO_PUBLIC
int ofb_final(struct OFB_STATE *state,
              struct BLOCK_STATE *cipher_state,
              void *out, size_t *out_len);

/** @see \c block_mode_limits()
**/
ORDO_PUBLIC
int ofb_limits(prim_t cipher, struct BLOCK_MODE_LIMITS *limits);

/** Gets the size in bytes of an \c OFB_STATE.
***
*** @returns The size in bytes of the structure.
***
*** @remarks Binary compatibility layer.
**/
ORDO_PUBLIC
size_t ofb_bsize(void);

/*===----------------------------------------------------------------------===*/

#ifdef __cplusplus
}
#endif

#endif
