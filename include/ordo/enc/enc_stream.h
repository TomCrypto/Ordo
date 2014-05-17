/*===-- enc/enc_stream.h -------------------------------*- PUBLIC -*- H -*-===*/
/**
/// @file
/// @brief Module
///
/// Interface to encrypt plaintext and  decrypt ciphertext with various stream
/// ciphers.
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

// TMP: max cipher state 2048 bytes

struct ENC_STREAM_CTX
{
    const struct STREAM_CIPHER *cipher;
    unsigned char state[2048];
};

/** Initializes a stream encryption context.
///
/// @param [in,out] ctx            A stream encryption context.
/// @param [in]     key            The cryptographic key to use.
/// @param [in]     key_size       The size, in bytes, of the key.
/// @param [in]     params         Stream cipher specific parameters.
///
/// @returns \c #ORDO_SUCCESS on success, else an error code.
**/
ORDO_PUBLIC
int enc_stream_init(struct ENC_STREAM_CTX *ctx,
                    const void *key,
                    size_t key_size,
                    const struct STREAM_CIPHER *cipher,
                    const void *params);

/** Encrypts or decrypts a data buffer.
///
/// @param [in,out] ctx            A stream encryption context.
/// @param [in,out] buffer         The plaintext or ciphertext buffer.
/// @param [in]     len            Number of bytes to read from the buffer.
///
/// @remarks By nature, stream  ciphers encrypt and decrypt data the same way,
///          in other  words, if you encrypt data twice, you will get back the
///          original data.
///
/// @remarks Stream encryption is always done in place by design.
**/
ORDO_PUBLIC
void enc_stream_update(struct ENC_STREAM_CTX *ctx,
                       void *buffer,
                       size_t len);

/** Finalizes a stream encryption context.
///
/// @param [in,out] ctx            A stream encryption context.
**/
ORDO_PUBLIC
void enc_stream_final(struct ENC_STREAM_CTX *ctx);

/** Performs a deep copy of one context into another.
///
/// @param [out]    dst            The destination context.
/// @param [in]     src            The source context.
///
/// @remarks The destination context should have been allocated using the same
///          primitive(s) as the source context, and mustn't be initialized.
///
/// @remarks The source context must be initialized.
**/
ORDO_PUBLIC
void enc_stream_copy(struct ENC_STREAM_CTX *dst,
                     const struct ENC_STREAM_CTX *src);

/** Queries a stream cipher for its key length.
///
/// @param [in]     cipher         The stream cipher to probe.
/// @param [in]     key_len        A suggested key length.
///
/// @returns \c  key_len if and only if \c  key_len is a valid  key length for
///          this  stream  cipher. Otherwise, returns  the nearest  valid  key
///          length  greater than \c  key_len. However, if  no such key length
///          exists, it will  return the  largest key  length  admitted by the
///          stream cipher.
**/
ORDO_PUBLIC
size_t enc_stream_key_len(const struct STREAM_CIPHER *cipher,
                          size_t key_len);

/*===----------------------------------------------------------------------===*/

#ifdef __cplusplus
}
#endif

#endif
