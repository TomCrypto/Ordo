#ifndef ORDO_ENC_BLOCK_H
#define ORDO_ENC_BLOCK_H

#include "ordo/enc/block_modes.h"

/******************************************************************************/

/*!
 * @file enc_block.h
 * @brief Block cipher encryption module.
 *
 * Module to encrypt plaintext and decrypt ciphertext with different block
 * ciphers and modes of operation. Note it is always possible to skip this
 * API and directly use the lower-level functions available in the individual
 * mode of operation headers, but this interface abstracts away some of the
 * more boilerplate details and so should be preferred.
 *
 * If you wish to use the lower level API, you will need to manage your block
 * cipher contexts yourself, which can give more flexibility in some
 * particular cases but is often unnecessary.
 *
 * The padding algorithm for modes of operation which use padding is PKCS7
 * (RFC 5652), which appends N bytes of value \c N, where \c N is the number
 * of padding bytes required, in bytes (between 1 and the block cipher's
 * block size).
*/

#ifdef __cplusplus
extern "C" {
#endif

struct ENC_BLOCK_CTX;

/*! Allocates a new block encryption context.
 @param cipher The block cipher to use.
 @param mode The block mode of operation to use.
 @return Returns the allocated block encryption context, or nil if an
         allocation error occurred.
*/
struct ENC_BLOCK_CTX* enc_block_alloc(const struct BLOCK_CIPHER *cipher,
                                      const struct BLOCK_MODE *mode);

/*! Initializes a block encryption context.
 @param ctx An allocated block encryption context.
 @param key The cryptographic key to use for encryption.
 @param key_len The length, in bytes, of the key.
 @param iv The initialization vector to use.
 @param iv_len The length, in bytes, of the initialization vector.
 @param direction The encryption direction: 1 is encryption, 0 decryption.
 @param cipher_params Block cipher specific parameters.
 @param mode_params Mode of operation specific parameters.
 @return Returns \c #ORDO_SUCCESS on success, or an error code.
 @remarks The initialization vector may be nil, if the mode of operation
          does not require one; consult the documentation of the mode of
          operation to find out what it expects.
*/
int enc_block_init(struct ENC_BLOCK_CTX* ctx,
                   const void *key, size_t key_len,
                   const void *iv, size_t iv_len,
                   int direction,
                   const void *cipher_params,
                   const void *mode_params);

/*! Encrypts or decrypts a data buffer.
 @param ctx An initialized block encryption context.
 @param in The plaintext or ciphertext buffer.
 @param in_len Number of bytes to read from the \c in buffer.
 @param out The ciphertext or plaintext (respectively) buffer.
 @param out_len The number of bytes written to the \c out buffer.
 @remarks This function may not immediately encrypt all data fed into it, and
          will write the amount of input bytes effectively encrypted in
          \c out_len. However, it \b does \b not mean that the plaintext left
          over has been "rejected" or "ignored". It has been taken into
          account, but the corresponding ciphertext simply cannot be produced
          until more data is fed into it (or \c enc_block_final() is called).
 @remarks Some modes of operation always process all input data, in which
          case they may allow \c out_len to be nil; check the documentation
          of the relevant mode of operation.
*/
void enc_block_update(struct ENC_BLOCK_CTX *ctx,
                      const void *in, size_t in_len,
                      void *out, size_t *out_len);

/*! Finalizes a block encryption context, returning any remaining plaintext
    or ciphertext.
 @param ctx An initialized block encryption context.
 @param out A buffer in which to write the remaining plaintext or ciphertext.
 @param out_len The number of bytes written to the \c out buffer.
 @return Returns \c #ORDO_SUCCESS on success, or an error code.
 @remarks This function will return up to one block size's worth of data, and
          may not return any data at all. As an example, for the CBC mode of
          operation with padding enabled, this function will, for encryption,
          append padding to the final plaintext block and return this padding
          block, whereas for decryption, it will take that padding block and
          strip the padding off, returning the last few bytes of plaintext.
 @remarks Some modes of operation always process all input data, in which
          case they may allow \c out_len to be nil; check the documentation
          of the relevant mode of operation.
*/
int enc_block_final(struct ENC_BLOCK_CTX *ctx,
                    void *out, size_t *out_len);

/*! Frees a block encryption context.
 @param ctx A block encryption context.
 @remarks The context need not have been initialized.
*/
void enc_block_free(struct ENC_BLOCK_CTX *ctx);

/*! Performs a deep copy of one context into another.
 @param dst The destination context.
 @param src The source context.
 @remarks Both contexts must have been allocated with the same block cipher,
          block mode, and the exact same parameters for both (unless the
          parameter documentation states otherwise) else the function's
          behavior is undefined.
*/
void enc_block_copy(struct ENC_BLOCK_CTX *dst,
                    const struct ENC_BLOCK_CTX *src);
                    
size_t enc_block_key_len(const struct BLOCK_CIPHER *cipher,
                         size_t key_len);

size_t enc_block_iv_len(const struct BLOCK_CIPHER *cipher,
                        const struct BLOCK_MODE *mode,
                        size_t iv_len);

#ifdef __cplusplus
}
#endif

#endif
