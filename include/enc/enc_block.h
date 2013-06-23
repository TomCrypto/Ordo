#ifndef ORDO_ENC_BLOCK_H
#define ORDO_ENC_BLOCK_H

#include <enc/block_modes.h>

/******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file enc_block.h
 *
 * \brief Block cipher encryption module.
 *
 * Interface to encrypt plaintext and decrypt ciphertext with different block ciphers and modes of operation.
 * Note it is always possible to skip this API and directly use the lower-level functions available in the individual
 * mode of operation headers, but this interface abstracts away some of the more boilerplate details and so should be
 * preferred.
 *
 * If you wish to use the lower level API, you will need to manage your block cipher contexts yourself, which can give
 * more flexibility in some particular cases but is often unnecessary.
 *
 * The padding algorithm for modes of operation which use padding is PKCS7 (RFC 5652), which appends N bytes of value
 * N, where N is the number of padding bytes required, in bytes (between 1 and the block cipher's block size).
*/

struct ENC_BLOCK_CTX;

/*! This function returns an allocated block cipher encryption context using a specific block cipher and mode of
 * operation.
 \param cipher The block cipher object to be used.
 \param mode The mode of operation object to be used.
 \return Returns the allocated block cipher encryption context, or 0 if an error occurred. */
struct ENC_BLOCK_CTX* enc_block_alloc(const struct BLOCK_CIPHER* cipher, const struct BLOCK_MODE* mode);

/*! This function initializes a block cipher encryption context for encryption, provided a key, initialization vector,
 * and cipher/mode-specific parameters.
 \param ctx An allocated block cipher encryption context.
 \param key A buffer containing the key to use for encryption.
 \param keySize The size, in bytes, of the encryption key.
 \param iv This points to the initialization vector.
 \param cipherParams This points to specific cipher parameters, set to zero for default behavior.
 \param modeParams This points to specific mode of operation parameters, set to zero for default behavior.
 \param dir This represents the dir of encryption, set to 1 for encryption and 0 for decryption.
 \return Returns \c ORDO_SUCCESS on success, and a negative value on error.
 \remark The initialization vector may be zero, if the mode of operation does not require one. */
int enc_block_init(struct ENC_BLOCK_CTX* ctx,
                   const void* key, size_t key_len,
                   const void* iv, size_t iv_len,
                   int direction,
                   const void* cipher_params,
                   const void* mode_params);

/*! This function encrypts or decrypts a buffer of a given length using the provided block cipher encryption context.
 \param ctx The block cipher encryption context to use. This context must have been allocated and initialized.
 \param in This points to a buffer containing plaintext (or ciphertext).
 \param inlen This contains the size of the \c in buffer, in bytes.
 \param out This points to a buffer which will contain the plaintext (or ciphertext).
 \param outlen This points to a variable which will contain the number of bytes written to \c out.
 \remark See \c blockEncryptModeUpdate() for remarks about output buffer size. */
void enc_block_update(struct ENC_BLOCK_CTX* ctx,
                          const void* in, size_t inlen,
                          void* out, size_t* outlen);

/*! This function finalizes a block cipher encryption context, and will process and return any leftover plaintext or
 * ciphertext.
 \param ctx The block cipher encryption context to use. This context must have been allocated and initialized.
 \param out This points to a buffer which will contain any remaining plaintext (or ciphertext).
 \param outlen This points to a variable which will contain the number of bytes written to \c out.
 \return Returns \c ORDO_SUCCESS on success, and a negative value on error.
 \remark Once this function returns, the passed context can no longer be used for encryption or decryption.
 \remark See \c blockEncryptModeFinal() for remarks. */
int enc_block_final(struct ENC_BLOCK_CTX* ctx, void* out, size_t* outlen);

/*! This function frees (deallocates) an initialized block cipher encryption context.
 \param ctx The block cipher encryption context to be freed. This context needs to at least have been allocated.
 \remark Once this function returns, the passed context may no longer be used anywhere and sensitive information will
 be wiped. Do not call this function if \c enc_block_alloc() failed, as the latter correctly frees dangling context
 buffers in case of error. */
void enc_block_free(struct ENC_BLOCK_CTX* ctx);

void enc_block_copy(struct ENC_BLOCK_CTX *dst,
                    const struct ENC_BLOCK_CTX *src);

#ifdef __cplusplus
}
#endif

#endif
