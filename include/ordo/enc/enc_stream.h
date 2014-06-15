/*===-- enc/enc_stream.h -------------------------------*- PUBLIC -*- H -*-===*/
/**
*** @file
*** @brief Module
***
*** Interface to encrypt plaintext and  decrypt ciphertext with various stream
*** ciphers.
**/
/*===----------------------------------------------------------------------===*/

#ifndef ORDO_ENC_STREAM_H
#define ORDO_ENC_STREAM_H

/** @cond **/
#include "ordo/common/interface.h"
/** @endcond **/

#include "ordo/primitives/stream_ciphers.h"

#ifdef __cplusplus
extern "C" {
#endif

/*===----------------------------------------------------------------------===*/

#define ENC_STREAM_CTX STREAM_STATE

/** Initializes a stream encryption context.
***
*** @param [in,out] ctx            A stream encryption context.
*** @param [in]     key            The cryptographic key to use.
*** @param [in]     key_size       The size, in bytes, of the key.
*** @param [in]     params         Stream cipher specific parameters.
***
*** @returns \c #ORDO_SUCCESS on success, else an error code.
**/
#define enc_stream_init stream_cipher_init

/** Encrypts or decrypts a data buffer.
***
*** @param [in,out] ctx            A stream encryption context.
*** @param [in,out] buffer         The plaintext or ciphertext buffer.
*** @param [in]     len            Number of bytes to read from the buffer.
***
*** @remarks By nature, stream  ciphers encrypt and decrypt data the same way,
***          in other  words, if you encrypt data twice, you will get back the
***          original data.
***
*** @remarks Stream encryption is always done in place by design.
**/
#define enc_stream_update stream_cipher_update

/** Finalizes a stream encryption context.
***
*** @param [in,out] ctx            A stream encryption context.
**/
#define enc_stream_final stream_cipher_final

/** Queries a stream cipher for its key length.
***
*** @param [in]     cipher         The stream cipher to probe.
*** @param [in]     key_len        A suggested key length.
***
*** @returns \c  key_len if and only if \c  key_len is a valid  key length for
***          this  stream  cipher. Otherwise, returns  the nearest  valid  key
***          length  greater than \c  key_len. However, if  no such key length
***          exists, it will  return the  largest key  length  admitted by the
***          stream cipher.
**/
ORDO_PUBLIC
size_t enc_stream_key_len(prim_t cipher,
                          size_t key_len);

/*===----------------------------------------------------------------------===*/

#ifdef __cplusplus
}
#endif

#endif
