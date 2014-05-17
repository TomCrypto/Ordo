/*===-- enc/block_modes/ofb.h --------------------------*- PUBLIC -*- H -*-===*/
/**
/// @file
/// @brief Primitive
///
/// The  OFB   mode  generates  a   keystream  by  repeatedly   encrypting  an
/// initialization vector,  effectively turning a  block cipher into  a stream
/// cipher. As such,  OFB mode requires no padding, and  outlen will always be
/// equal to inlen.
///
/// Note that the  OFB keystream is independent of the  plaintext, so a key/iv
/// pair must  never be used  for more than one  message. This also  means the
/// block cipher's inverse permutation is never used.
///
/// \c ofb_final() accepts 0 as an argument for \c outlen, since by design the
/// OFB mode of operation does not produce any final data. However, if a valid
/// pointer is passed, its value will be set to zero as expected.
**/
/*===----------------------------------------------------------------------===*/

#ifndef ORDO_OFB_MODE_H
#define ORDO_OFB_MODE_H

/** @cond **/
#include "ordo/common/interface.h"
/** @endcond **/

#include "ordo/primitives/block_modes/mode_params.h"
#include "ordo/primitives/block_ciphers.h"

#ifdef __cplusplus
extern "C" {
#endif

/*===----------------------------------------------------------------------===*/

struct OFB_STATE;

/** @see \c block_mode_init()
**/
ORDO_PUBLIC
int ofb_init(struct OFB_STATE *state,
             const struct BLOCK_CIPHER *cipher,
             const void *cipher_state,
             const void *iv, size_t iv_len,
             int dir,
             const void *params);

/** @see \c block_mode_update()
**/
ORDO_PUBLIC
void ofb_update(struct OFB_STATE *state,
                const struct BLOCK_CIPHER *cipher,
                const void *cipher_state,
                const unsigned char *in, size_t in_len,
                unsigned char *out, size_t *out_len);

/** @see \c block_mode_final()
**/
ORDO_PUBLIC
int ofb_final(struct OFB_STATE *state,
              const struct BLOCK_CIPHER *cipher,
              const void *cipher_state,
              unsigned char *out, size_t *out_len);

/** @see \c block_mode_query()
**/
ORDO_PUBLIC
size_t ofb_query(const struct BLOCK_CIPHER *cipher,
                 int query, size_t value);

/*===----------------------------------------------------------------------===*/

#ifdef __cplusplus
}
#endif

#endif
