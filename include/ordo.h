#ifndef ORDO_ORDO_H
#define ORDO_ORDO_H

#include <enc/enc_stream.h>
#include <enc/enc_block.h>

#include <random/random.h>

#include <kdf/pbkdf2.h>
#include <auth/hmac.h>

/******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * @file ordo.h
 * @brief High-level library API.
 *
 * This is the highest-level API for Ordo, which forgoes the use of
 * cryptographic contexts completely,resulting in more concise code
 * at the cost of reduced flexibility. In other words, if you can
 * afford to use them, you probably should.
*/

/*! Initializes the library, calling all the \c load_* functions in each
 *  abstraction layer, allowing the use of functions such as \c RC4(),
 *  \c CBC(), and so on.
 @remarks This function should be called prior to using the library for most
          purposes.
*/
void ordo_init();

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
 @return Returns \c #ORDO_SUCCESS on success, or a negative value on failure.
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
                   const void *iv,  size_t iv_len,
                   const void *in,  size_t in_len,
                         void* out, size_t *out_len);

/*! Encrypts or decrypts a buffer using a stream cipher.
 @param cipher The stream cipher to use.
 @param params The stream cipher parameters.
 @param inout The plaintext or ciphertext buffer.
 @param inout_len The length in bytes of the buffer.
 @param key The cryptographic key to use for encryption.
 @param key_size The length, in bytes, of the key.
 @return Returns \c #ORDO_SUCCESS on success, or a negative value on failure.
 @remarks Stream ciphers do not, strictly speaking, require an initialization
          vector. If such a feature is required, it is recommended to use a
          key derivation function to derive a new encryption key from a
          "master" key and a nonce.
 @remarks Encryption is always done in place. If you need out-of-place
          encryption, make a copy of the plaintext buffer prior to encryption.
 @remarks By design, encryption and decryption are equivalent for stream
          ciphers.
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
 @return Returns \c #ORDO_SUCCESS on success, or a negative value on failure.
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
 @param in_len The length in bytes of the buffer.
 @param fingerprint A pointer to where the fingerprint will be written.
 @return Returns \c #ORDO_SUCCESS on success, or a negative value on failure.
 @remarks Do not use hash parameters which modify the hash function's output
          length, or this function's behavior is undefined.
*/
int ordo_hmac(const struct HASH_FUNCTION *hash, const void *params,
              const void *key, size_t key_len,
              const void *in, size_t len,
              void* fingerprint);

#ifdef __cplusplus
}
#endif

#endif
