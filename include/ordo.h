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

/*! Initializes the library: calls all the \c load_* functions in each
 * abstraction layer. After this function returns, all objects such as
 * \c RC4(), \c CBC(), and so on, may be used.
*/
void init_ordo();

/*! This function encrypts a buffer of a given length using a block cipher in a given mode of operation with the passed
 * parameters.
 \param in The plaintext buffer.
 \param inlen Number of bytes to read from the \c in buffer.
 \param out The ciphertext buffer, to which the ciphertext should be written.
 \param outlen This points to a variable which will contain the number of bytes written to \c out.
 \param cipher A block cipher object, describing the block cipher to use for encryption.
 \param mode The block cipher mode of operation to be used for encryption.
 \param key A buffer containing the key material to use for encryption.
 \param keySize The length, in bytes, of the \c key buffer.
 \param iv A buffer containing the initialization vector (this may be 0 if the mode of operation does not use an IV).
 \param cipherParams This points to specific block cipher parameters, set to zero for default behavior.
 \param modeParams This points to specific mode of operation parameters, set to zero for default behavior.
 \return Returns \c ORDO_SUCCESS on success, a negative error code on failure.
 \remark One downside of this function is that it is not possible to encrypt data in chunks - the whole plaintext must
 be available before encryption can begin. If your requirements make this unacceptable, you should use the encryption
 interface, located one level of abstraction lower - see enc_block.h. \n\n
 The out buffer should have enough space to contain the entire ciphertext, which may be larger than the plaintext if a
 mode which uses padding (with padding enabled) is used. See remarks about padding in enc_block.h. */
int ordo_enc_block(const struct BLOCK_CIPHER* cipher,
                   const void *cipher_params,
                   const struct BLOCK_MODE* mode,
                   const void *mode_params,
                   int direction,
                   const void *key, size_t key_len,
                   const void *iv,  size_t iv_len,
                   const void *in,  size_t in_len,
                         void* out, size_t *out_len);

/*! This function encrypts or decrypts a buffer of a given length using a stream cipher.
 \param inout The plaintext or ciphertext buffer.
 \param len Number of bytes to read from the \c inout buffer.
 \param cipher A stream cipher object, describing the stream cipher to use for encryption.
 \param key A buffer containing the key material to use for encryption.
 \param keySize The length, in bytes, of the \c key buffer.
 \param cipherParams This points to specific block cipher parameters, set to zero for default behavior.
 \return Returns \c ORDO_SUCCESS on success, a negative error code on failure.
 \remark Stream ciphers are different from block ciphers in multiple ways: \n
 - they do not require an IV because there is no standard way to add initialization vectors to a stream cipher.
 - no mode of operation is required as stream ciphers work by generating a keystream and combining it with the
 plaintext or ciphertext (so they are a "mode" in themselves). \n
 - there is no difference between encryption and decryption: encrypting the ciphertext again will produce the plaintext
 and vice versa. \n
 - the encryption or decryption is done in-place directly in the \c inout buffer, since the ciphertext is always the
 same length as the plaintext. If you need two different buffers, make a copy of the plaintext before encrypting. */
int ordo_enc_stream(const struct STREAM_CIPHER *cipher, const void *params,
                    const void *key,    size_t key_len,
                          void *buffer, size_t len);

/*! This function hashes a buffer of a given length into a digest using a hash function.
 \param in The input buffer to hash.
 \param len Number of bytes to read from the \c in buffer.
 \param out The buffer in which to put the digest.
 \param hash A hash function object, describing the hash function to use.
 \param hashParams This points to specific hash function parameters, set to zero for default behavior.
 \return Returns \c ORDO_SUCCESS on success, a negative error code on failure. */
int ordo_digest(const struct HASH_FUNCTION *hash, const void *params,
                const void *in, size_t len,
                void *digest);

/*! This function returns the HMAC of a buffer using a key with any hash function.
 \param in The input buffer to hash.
 \param len Number of bytes to read from the \c in buffer.
 \param key The key to use.
 \param keySize The length of the key to use, in bytes.
 \param out The buffer in which to put the digest.
 \param hash A hash function object, describing the hash function to use.
 \param hashParams This points to specific hash function parameters, set to zero for default behavior.
 \return Returns \c ORDO_SUCCESS on success, a negative error code on failure.
 \remark Note the hash parameters only affect the inner hash (the one hashing the buffer),
 not the outer one or the potential key-processing one.*/
int ordo_hmac(const struct HASH_FUNCTION *hash, const void *params,
              const void *key, size_t key_len,
              const void *in,  size_t len,
              void* fingerprint);

#ifdef __cplusplus
}
#endif

#endif
