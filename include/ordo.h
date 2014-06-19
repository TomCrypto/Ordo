/*===-- ordo.h -----------------------------------------*- PUBLIC -*- H -*-===*/
/**
*** @file
*** @brief Wrapper
***
*** This  is  the  highest-level  API  for Ordo,  which  forgoes  the  use  of
*** cryptographic contexts completely,  resulting in more concise  code at the
*** cost of  reduced flexibility - in other  words, if you  can afford  to use
*** them, you probably want to do so.
***
*** Usage snippet (compare to snippet in \c digest.h):
***
*** @code
*** const char x[] = "Hello, world!";
*** unsigned char out[32]; // 256 bits
*** int err = ordo_digest(HASH_SHA256, 0, x, strlen(x), out);
*** if (err) printf("Error encountered!\n");
*** // out = 315f5bdb76d0...
*** @endcode
***
*** Some specialized headers are *not* included by this header - these are the
*** endianness header & all primitive headers (their parameters are included),
*** if you need their functionality please include them explicitly.
**/
/*===----------------------------------------------------------------------===*/

#ifndef ORDO_ORDO_H
#define ORDO_ORDO_H

/** @cond **/
#include "ordo/common/interface.h"
/** @endcond **/

#include "ordo/common/version.h"
#include "ordo/common/error.h"
#include "ordo/common/query.h"

#include "ordo/enc/enc_stream.h"
#include "ordo/enc/enc_block.h"

#include "ordo/kdf/pbkdf2.h"

#include "ordo/misc/os_random.h"
#include "ordo/misc/curve25519.h"

#ifdef __cplusplus
extern "C" {
#endif

/*===----------------------------------------------------------------------===*/

/** Encrypts or decrypts data using a block cipher with a mode of operation.
***
*** @param [in]     cipher         The block cipher to use.
*** @param [in]     cipher_params  The block cipher parameters.
*** @param [in]     mode           The mode of operation to use.
*** @param [in]     mode_params    The mode of operation parameters.
*** @param [in]     direction      1 for encryption, 0 for decryption.
*** @param [in]     key            The cryptographic key to use.
*** @param [in]     key_len        The length in bytes of the key.
*** @param [in]     iv             The initialization vector.
*** @param [in]     iv_len         The length in bytes of the IV.
*** @param [in]     in             The input plaintext/ciphertext buffer.
*** @param [in]     in_len         The length of the input buffer.
*** @param [out]    out            The output ciphertext/plaintext buffer.
*** @param [out]    out_len        The length of the output buffer.
***
*** @returns \c #ORDO_SUCCESS on success, else an error code.
***
*** @remarks The \c out buffer should be large enough to accomodate the entire
***          ciphertext which may be larger than the plaintext if a mode where
***          padding is enabled and used, see padding notes in \c enc_block.h.
**/
ORDO_PUBLIC
int ordo_enc_block(prim_t cipher, const void *cipher_params,
                   prim_t mode, const void *mode_params,
                   int direction,
                   const void *key, size_t key_len,
                   const void *iv, size_t iv_len,
                   const void *in, size_t in_len,
                   void *out, size_t *out_len);

/** Encrypts or decrypts data using a stream cipher.
***
*** @param [in]     cipher         The stream cipher to use.
*** @param [in]     params         The stream cipher parameters.
*** @param [in,out] inout          The plaintext or ciphertext buffer.
*** @param [in]     len            The length, in bytes, of the buffer.
*** @param [in]     key            The cryptographic key to use.
*** @param [in]     key_len        The length, in bytes, of the key.
***
*** @returns \c #ORDO_SUCCESS on success, else an error code.
***
*** @remarks Stream ciphers do not strictly speaking require an initialization
***          vector - if such a feature is needed, it is  recommended to use a
***          key derivation function to derive an encryption key from a master
***          key using a pseudorandomly generated nonce.
***
*** @remarks Encryption  is always done in  place. If you require out-of-place
***          encryption, make a copy of the plaintext prior to encryption.
***
*** @warning By design, encryption  and decryption are  equivalent for  stream
***          ciphers - an implication is that encrypting a message twice using
***          the same key yields the original message.
**/
ORDO_PUBLIC
int ordo_enc_stream(prim_t cipher, const void *params,
                    const void *key, size_t key_len,
                    void *inout, size_t len);

/** Calculates the digest of a buffer using any hash function.
***
*** @param [in]     hash           The hash function to use.
*** @param [in]     params         The hash function parameters.
*** @param [in]     in             The input buffer to hash.
*** @param [in]     in_len         The length in bytes of the buffer.
*** @param [out]    digest         The output buffer for the digest.
***
*** @returns \c #ORDO_SUCCESS on success, else an error code.
**/
ORDO_PUBLIC
int ordo_digest(prim_t hash, const void *params,
                const void *in, size_t in_len,
                void *digest);

/** Calculates the HMAC fingerprint of a buffer using any hash function.
***
*** @param [in]     hash           The hash function to use.
*** @param [in]     params         The hash function parameters.
*** @param [in]     key            The key to use for authentication.
*** @param [in]     key_len        The length in bytes of the key.
*** @param [in]     in             The input buffer to authenticate.
*** @param [in]     in_len         The length, in bytes, of the input buffer.
*** @param [out]    fingerprint    The output buffer for the fingerprint.
***
*** @returns \c #ORDO_SUCCESS on success, else an error code.
**/
ORDO_PUBLIC
int ordo_hmac(prim_t hash, const void *params,
              const void *key, size_t key_len,
              const void *in, size_t in_len,
              void *fingerprint);

/*===----------------------------------------------------------------------===*/

#ifdef __cplusplus
}
#endif

#endif
