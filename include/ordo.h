#ifndef ORDO_ORDO_H
#define ORDO_ORDO_H

#include "ordo/common/version.h"
#include "ordo/common/utils.h"

#include "ordo/enc/enc_stream.h"
#include "ordo/enc/enc_block.h"

#include "ordo/kdf/pbkdf2.h"
#include "ordo/auth/hmac.h"

#include "ordo/misc/os_random.h"

/******************************************************************************/

/*!
 * @file ordo.h
 * @brief High-level library API.
 *
 * This is the highest-level API for Ordo, which forgoes the use of
 * cryptographic contexts completely,resulting in more concise code
 * at the cost of reduced flexibility. In other words, if you can
 * afford to use them, you probably should.
*/

#ifdef __cplusplus
extern "C" {
#endif

/*! Initializes the library.
 *  @returns Returns #ORDO_SUCCESS on success, or an error code.
 *  @remarks This function should be called prior to using the library for
             most purposes.
*/
int ordo_init(void);

/*! Encrypts or decrypts a buffer using a block cipher in an encryption-only
 *  mode of operation.
 @param cipher The block cipher to use.
 @param cipher_params The block cipher parameters.
 @param mode The mode of operation to use.
 @param mode_params The mode of operation parameters.
 @param direction The encryption direction: 1 for encryption, 0 for decryption.
 @param key The cryptographic key to use for encryption.
 @param key_len The length in bytes of the key.
 @param iv The initialization vector.
 @param iv_len The length in bytes of the initialization vector.
 @param in The input plaintext (or ciphertext) buffer.
 @param in_len The length of the input buffer.
 @param out The output ciphertext (or, respectively, plaintext) buffer.
 @param out_len The length of the output buffer.
 @return Returns \c #ORDO_SUCCESS on success, or an error code.
 @remarks The \c out buffer should have enough space to contain the entire
          ciphertext, which may be larger than the plaintext if a mode
          which padding (with padding enabled) is used. See remarks
          about padding in \c enc_block.h.
*/
int ordo_enc_block(const struct BLOCK_CIPHER* cipher,
                   const void *cipher_params,
                   const struct BLOCK_MODE* mode,
                   const void *mode_params,
                   int direction,
                   const void *key, size_t key_len,
                   const void *iv, size_t iv_len,
                   const void *in, size_t in_len,
                   void* out, size_t *out_len);

/*! Encrypts or decrypts a buffer using a stream cipher.
 @param cipher The stream cipher to use.
 @param params The stream cipher parameters.
 @param inout The plaintext or ciphertext buffer.
 @param len The length, in bytes, of the buffer.
 @param key The cryptographic key to use for encryption.
 @param key_len The length, in bytes, of the key.
 @return Returns \c #ORDO_SUCCESS on success, or an error code.
 @remarks Stream ciphers do not, strictly speaking, require an initialization
          vector. If such a feature is required, it is recommended to use a
          key derivation function to derive a new encryption key from a
          "master" key and a nonce.
 @remarks Encryption is always done in place. If you need out-of-place
          encryption, make a copy of the plaintext buffer prior to encryption.
 @remarks By design, encryption and decryption are equivalent for stream
          ciphers. An implication of this, is that encrypting a message
          twice with the same key yields the original message.
*/
int ordo_enc_stream(const struct STREAM_CIPHER *cipher, const void *params,
                    const void *key, size_t key_len,
                    void *inout, size_t len);

/*! Returns the digest of a buffer.
 @param hash The hash function to use.
 @param params The hash function parameters.
 @param in The input buffer to hash.
 @param in_len The length in bytes of the buffer.
 @param digest The buffer in which to put the digest.
 @return Returns \c #ORDO_SUCCESS on success, or an error code.
*/
int ordo_digest(const struct HASH_FUNCTION *hash, const void *params,
                const void *in, size_t in_len,
                void *digest);

/*! Returns the HMAC fingerprint of a buffer.
 @param hash The hash function to use.
 @param params The hash function parameters.
 @param key The key to use for authentication.
 @param key_len The length in bytes of the key.
 @param in The input buffer to authenticate.
 @param in_len The length, in bytes, of the input buffer.
 @param fingerprint A pointer to where the fingerprint will be written.
 @return Returns \c #ORDO_SUCCESS on success, or an error code.
 @remarks Do not use hash parameters which modify the hash function's output
          length, or this function's behavior is undefined.
*/
int ordo_hmac(const struct HASH_FUNCTION *hash, const void *params,
              const void *key, size_t key_len,
              const void *in, size_t in_len,
              void* fingerprint);

#ifdef __cplusplus
}
#endif

#endif
