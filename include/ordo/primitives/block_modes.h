/*===-- enc/block_modes.h ------------------------------*- PUBLIC -*- H -*-===*/
/**
*** @file
*** @brief Abstraction Layer
***
*** This abstraction  layer declares all the  block modes of operation  in the
*** library, making them available to higher level modules.
***
*** Note "block cipher mode of operation" is shortened to "block mode" in code
*** and documentation to minimize noise and redundancy.
**/
/*===----------------------------------------------------------------------===*/

#ifndef ORDO_BLOCK_MODES_H
#define ORDO_BLOCK_MODES_H

/** @cond **/
#include "ordo/common/interface.h"
#include "ordo/common/identification.h"
#include "ordo/primitives/block_modes/mode_params.h"
/** @endcond **/

#include "ordo/primitives/block_ciphers.h"

#ifdef __cplusplus
extern "C" {
#endif

/*===----------------------------------------------------------------------===*/

#define block_mode_init                  ordo_block_mode_init
#define block_mode_update                ordo_block_mode_update
#define block_mode_final                 ordo_block_mode_final
#define block_mode_query                 ordo_block_mode_query
#define block_mode_bsize                 ordo_block_mode_bsize

/*===----------------------------------------------------------------------===*/

/** Initializes a block mode state.
***
*** @param [in,out] state          A block mode state.
*** @param [in]     cipher_state   A block cipher state.
*** @param [in]     iv             The initialization vector to use.
*** @param [in]     iv_len         The length, in bytes, of the IV.
*** @param [in]     direction      1 for encryption, 0 for decryption.
*** @param [in]     primitive      A block mode primitive.
*** @param [in]     params         Block mode specific parameters.
***
*** @returns \c #ORDO_SUCCESS on success, else an error code.
**/
ORDO_PUBLIC
int block_mode_init(struct BLOCK_MODE_STATE *state,
                    struct BLOCK_STATE *cipher_state,
                    const void *iv, size_t iv_len,
                    int direction,
                    prim_t primitive, const void *params);

/** Encrypts or decrypts a buffer.
***
*** @param [in,out] state          A block mode state.
*** @param [in]     cipher_state   A block cipher state.
*** @param [in]     in             The input buffer.
*** @param [in]     in_len         The length, in bytes, of the input.
*** @param [out]    out            The output buffer.
*** @param [out]    out_len        A pointer to an  integer to  which to write
***                                the  number of  output  bytes  that  can be
***                                returned to the user. Remaining  input data
***                                has \b not been ignored  and should  not be
***                                passed again.
***
*** @warning In-place  encryption (by  letting \c in be the  same buffer as \c
***          out) is always supported, however the buffers may \b not overlap.
**/
ORDO_PUBLIC
void block_mode_update(struct BLOCK_MODE_STATE *state,
                       struct BLOCK_STATE *cipher_state,
                       const void *in, size_t in_len,
                       void *out, size_t *out_len);

/** Finalizes a block mode state.
***
*** @param [in,out] state          A block mode state.
*** @param [in]     cipher_state   A block cipher state.
*** @param [out]    out            The output buffer.
*** @param [out]    out_len        A  pointer to an  integer to which to store
***                                the number of bytes written to \c out.
***
*** @returns \c #ORDO_SUCCESS on success, else an error code.
***
*** @remarks This function will return any input bytes which were not returned
***          by calls to \c block_mode_update() (in the correct order).
**/
ORDO_PUBLIC
int block_mode_final(struct BLOCK_MODE_STATE *state,
                     struct BLOCK_STATE *cipher_state,
                     void *out, size_t *out_len);

/** Queries a block mode for suitable parameters.
***
*** @param [in]     mode           A block mode primitive.
*** @param [in]     cipher         A block cipher primitive.
*** @param [in]     query          A query code.
*** @param [in]     value          A suggested value.
***
*** @returns A suitable parameter of type \c query based on \c value.
***
*** @see query.h
**/
ORDO_PUBLIC
size_t block_mode_query(prim_t mode, prim_t cipher,
                        int query, size_t value);

/** Gets the size in bytes of a \c BLOCK_MODE_STATE.
***
*** @returns The size in bytes of the structure.
***
*** @remarks Binary compatibility layer.
**/
ORDO_PUBLIC
size_t block_mode_bsize(void);

/*===----------------------------------------------------------------------===*/

#ifdef __cplusplus
}
#endif

#endif
