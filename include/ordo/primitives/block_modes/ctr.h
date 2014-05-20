/*===-- enc/block_modes/ctr.h --------------------------*- PUBLIC -*- H -*-===*/
/**
/// @file
/// @brief Primitive
///
/// The  CTR mode  generates a  keystream by  repeatedly encrypting  a counter
/// starting  from some  initialization  vector, effectively  turning a  block
/// cipher into  a stream cipher. As  such, CTR mode requires  no padding, and
/// outlen will always be equal to inlen.
///
/// Note that the  CTR keystream is independent of the  plaintext, and is also
/// spatially  coherent (using  a given  initialization vector  on a  len-byte
/// message will "use up" len bytes of the keystream) so care must be taken to
/// avoid  reusing the  initialization vector  in an  insecure way.  This also
/// means the block cipher's inverse permutation is never used.
///
/// \c ctr_final() accepts 0 as an argument for \c outlen, since by design the
/// CTR mode of operation does not produce any final data. However, if a valid
/// pointer is passed, its value will be set to zero as expected.
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
size_t ctr_query(enum BLOCK_CIPHER cipher,
                 int query, size_t value);

/*===----------------------------------------------------------------------===*/

#ifdef __cplusplus
}
#endif

#endif
