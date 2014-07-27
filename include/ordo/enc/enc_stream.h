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

#define enc_stream_init                  ordo_enc_stream_init
#define enc_stream_update                ordo_enc_stream_update
#define enc_stream_final                 ordo_enc_stream_final
#define enc_stream_key_len               ordo_enc_stream_key_len
#define enc_stream_bsize                 ordo_enc_stream_bsize

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
#define ordo_enc_stream_init stream_init

/** Encrypts or decrypts a data buffer.
***
*** @param [in,out] ctx            A stream encryption context.
*** @param [in,out] buffer         The plaintext or ciphertext buffer.
*** @param [in]     len            Number of bytes to read from the buffer.
***
*** @warning By nature, stream  ciphers encrypt and decrypt data the same way,
***          in other  words, if you encrypt data twice, you will get back the
***          original data.
***
*** @remarks Stream encryption is always done in place by design.
**/
#define ordo_enc_stream_update stream_update

/** Finalizes a stream encryption context.
***
*** @param [in,out] ctx            A stream encryption context.
**/
#define ordo_enc_stream_final stream_final

/** Returns the key length of a stream cipher.
***
*** @param [in]     cipher         A stream cipher primitive.
*** @param [in]     key_len        A suggested key length.
***
*** @returns A suitable key length to use for this cipher.
**/
ORDO_PUBLIC
size_t enc_stream_key_len(prim_t cipher,
                          size_t key_len);

/** Gets the size in bytes of an \c ENC_STREAM_CTX.
***
*** @returns The size in bytes of the structure.
***
*** @remarks Binary compatibility layer.
**/
#define ordo_enc_stream_bsize stream_bsize

/*===----------------------------------------------------------------------===*/

#ifdef __cplusplus
}
#endif

#endif
