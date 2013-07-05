#ifndef ORDO_ENC_STREAM_H
#define ORDO_ENC_STREAM_H

#include <primitives/primitives.h>

/******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * @file enc_stream.h
 * @brief Stream cipher encryption module.
 *
 * Interface to encrypt plaintext and decrypt ciphertext with various stream ciphers.
*/

struct ENC_STREAM_CTX;

/*! Allocates a new stream encryption context.
 @param cipher The stream cipher to use.
 @return Returns the allocated stream encryption context, or nil if an
         allocation error occurred.
*/
struct ENC_STREAM_CTX* enc_stream_alloc(const struct STREAM_CIPHER *cipher);

/*! Initializes a stream encryption context.
 @param ctx An allocated stream encryption context.
 @param key The cryptographic key to use for encryption.
 @param key_size The size, in bytes, of the key.
 @param params Stream cipher specific parameters.
 @return Returns \c #ORDO_SUCCESS on success, and a negative value on error.
*/
int enc_stream_init(struct ENC_STREAM_CTX *ctx,
                    const void *key,
                    size_t key_size,
                    const void *params);

/*! Encrypts or decrypts a data buffer.
 @param ctx An initialized stream encryption context.
 @param buffer The plaintext or ciphertext buffer.
 @param len Number of bytes to read from the buffer.
 @remarks By nature, stream ciphers encrypt and decrypt data the same way. In
          other words, if you encrypt data twice, you will get back the
          original data.
 @remarks Stream encryption is always done in place by design.
*/
void enc_stream_update(struct ENC_STREAM_CTX *ctx,
                       void *buffer,
                       size_t len);

/*! Frees a stream encryption context.
 @param ctx A stream encryption context.
 @remarks The context need not have been initialized.
*/
void enc_stream_free(struct ENC_STREAM_CTX *ctx);

/*! Performs a deep copy of one context into another.
 @param dst The destination context.
 @param src The source context.
 @remarks Both contexts must have been allocated with the same hash function,
          and the exact same parameters (unless the parameter documentation
          states otherwise) else the function's behavior is undefined.
*/
void enc_stream_copy(struct ENC_STREAM_CTX *dst,
                     const struct ENC_STREAM_CTX *src);

/*! Probes a stream cipher for its key length.
 @param cipher The stream cipher to probe.
 @param key_len A suggested key length.
 @returns Returns \c key_len if and only if \c key_len is a valid key length
          for this stream cipher. Otherwise, returns the nearest valid key
          length greater than \c key_len. However, if no such key length
          exists, it will return the largest key length admitted by the
          stream cipher.
*/
size_t enc_stream_key_len(const struct STREAM_CIPHER *cipher,
                          size_t key_len);

#ifdef __cplusplus
}
#endif

#endif
