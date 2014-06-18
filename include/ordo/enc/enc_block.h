/*===-- enc/enc_block.h --------------------------------*- PUBLIC -*- H -*-===*/
/**
*** @file
*** @brief Module
***
*** Module to  encrypt plaintext and  decrypt ciphertext with  different block
*** ciphers and  modes of operation. Note  it is always possible  to skip this
*** API and directly use the lower-level functions available in the individual
*** mode of operation  headers, but this interface abstracts away  some of the
*** more boilerplate details and so should be preferred.
***
*** If you wish to use the lower level API, you will need to manage your block
*** cipher  contexts  yourself,  which  can  give  more  flexibility  in  some
*** particular cases but is often unnecessary.
***
*** The padding  algorithm for modes of  operation which use padding  is PKCS7
*** (RFC 5652), which appends N bytes of value  \c N, where \c N is the number
*** of padding  bytes required,  in bytes  (between 1  and the  block cipher's
*** block size).
**/
/*===----------------------------------------------------------------------===*/

#ifndef ORDO_ENC_BLOCK_H
#define ORDO_ENC_BLOCK_H

/** @cond **/
#include "ordo/common/interface.h"
/** @endcond **/

#include "ordo/primitives/block_modes.h"

#ifdef __cplusplus
extern "C" {
#endif

/*===----------------------------------------------------------------------===*/

#define enc_block_init                   ordo_enc_block_init
#define enc_block_update                 ordo_enc_block_update
#define enc_block_final                  ordo_enc_block_final
#define enc_block_key_len                ordo_enc_block_key_len
#define enc_block_iv_len                 ordo_enc_block_iv_len
#define enc_block_bsize                  ordo_enc_block_bsize

/*===----------------------------------------------------------------------===*/

struct ENC_BLOCK_CTX
{
    struct BLOCK_STATE cipher;
    struct BLOCK_MODE_STATE mode;
};

/** Initializes a block encryption context.
***
*** @param [in,out] ctx            A block encryption context.
*** @param [in]     key            The cryptographic key to use.
*** @param [in]     key_len        The length, in bytes, of the key.
*** @param [in]     iv             The initialization vector to use.
*** @param [in]     iv_len         The length, in bytes, of the IV.
*** @param [in]     direction      1 for encryption, 0 for decryption.
*** @param [in]     cipher         The block cipher primitive to use.
*** @param [in]     cipher_params  Block cipher specific parameters.
*** @param [in]     mode           The block mode primitive to use.
*** @param [in]     mode_params    Mode of operation specific parameters.
***
*** @returns \c #ORDO_SUCCESS on success, else an error code.
***
*** @remarks The initialization vector may be 0, if the mode of operation does
***          not require one - consult the  documentation of the mode to  know
***          what it expects.
**/
ORDO_PUBLIC
int enc_block_init(struct ENC_BLOCK_CTX *ctx,
                   const void *key, size_t key_len,
                   const void *iv, size_t iv_len,
                   int direction,
                   prim_t cipher, const void *cipher_params,
                   prim_t mode, const void *mode_params);

/** Encrypts or decrypts a data buffer.
***
*** @param [in,out] ctx            A block encryption context.
*** @param [in]     in             The plaintext or ciphertext buffer.
*** @param [in]     in_len         Length, in bytes, of the input buffer.
*** @param [out]    out            The ciphertext or plaintext buffer.
*** @param [out]    out_len        The number of bytes written to \c out.
***
*** @remarks This function might not immediately encrypt all data fed into it,
***          and will write the amount of input bytes effectively encrypted in
***          \c out_len. However, it does \b not mean that the  plaintext left
***          over has  been "rejected" or "ignored". It \b has been taken into
***          account but the corresponding ciphertext simply can't be produced
***          until more  data is fed into it (or until \c enc_block_final() is
***          called).
***
*** @remarks Some modes of  operation always  process all input data, in which
***          case they  may allow \c out_len to be 0 - check the documentation
//           of the relevant mode of operation.
**/
ORDO_PUBLIC
void enc_block_update(struct ENC_BLOCK_CTX *ctx,
                      const void *in, size_t in_len,
                      void *out, size_t *out_len);

/** Finalizes a block encryption context.
***
*** @param [in,out] ctx            A block encryption context.
*** @param [out]    out            The ciphertext or plaintext buffer.
*** @param [out]    out_len        The number of bytes written to \c out.
***
*** @returns \c #ORDO_SUCCESS on success, else an error code.
***
*** @remarks The function will return up to one block size's worth of data and
***          may not  return any data at all. For example, for the CBC mode of
***          operation (with padding on), this function will, for  encryption,
***          append padding bytes to the final plaintext block, and return the
***          padding block, whereas for decryption, it will  take that padding
***          block and strip the padding off, returning the last  few bytes of
***          plaintext.
***
*** @remarks Some modes of  operation always  process all input data, in which
***          case they  may allow \c out_len to be 0 - check the documentation
***          of the relevant mode of operation.
**/
ORDO_PUBLIC
int enc_block_final(struct ENC_BLOCK_CTX *ctx,
                    void *out, size_t *out_len);

/** Queries the key length of a block cipher.
***
*** @param [in]     cipher         A block cipher primitive.
*** @param [in]     key_len        A suggested key length.
***
*** @returns A suitable key length to use for this cipher.
**/
ORDO_PUBLIC
size_t enc_block_key_len(prim_t cipher,
                         size_t key_len);

/** Queries the IV length of a block mode and block cipher.
***
*** @param [in]     cipher         A block cipher primitive.
*** @param [in]     mode           A block mode primitive.
*** @param [in]     iv_len         A suggested IV length.
***
*** @returns A suitable IV length to use for this mode and cipher.
**/
ORDO_PUBLIC
size_t enc_block_iv_len(prim_t cipher,
                        prim_t mode,
                        size_t iv_len);

/** Gets the size in bytes of an \c ENC_BLOCK_CTX.
***
*** @returns The size in bytes of the structure.
***
*** @remarks Binary compatibility layer.
**/
ORDO_PUBLIC
size_t enc_block_bsize(void);

/*===----------------------------------------------------------------------===*/

#ifdef __cplusplus
}
#endif

#endif
