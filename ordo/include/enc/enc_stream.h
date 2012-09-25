#ifndef ENC_STREAM_H
#define ENC_STREAM_H

/**
 * @file enc_stream.h
 *
 * \brief Stream cipher symmetric encryption.
 *
 * Interface to encrypt plaintext and decrypt ciphertext with various stream ciphers.
 *
 * @see enc_stream.c
 */

/* Library dependencies. */
#include <primitives/primitives.h>
#include <common/ordotypes.h>

/*! \brief Stream cipher symmetric encryption context.
 *
 * This structure describes a high-level symmetric encryption context, for stream ciphers. It only contains the stream
 * cipher's context, and is used only for consistency purposes with the block cipher encryption interface. */
typedef struct ENC_STREAM_CIPHER_CONTEXT
{
    /*! The stream cipher context. */
    STREAM_CIPHER_CONTEXT* cipherCtx;
} ENC_STREAM_CIPHER_CONTEXT;

/*! This function returns an allocated stream cipher encryption context using a specific stream cipher.
 \param cipher The stream cipher object to be used.
 \return Returns the allocated stream cipher encryption context, or 0 if an error occurred. */
ENC_STREAM_CIPHER_CONTEXT* encStreamCipherCreate(STREAM_CIPHER* cipher);

/*! This function initializes a stream cipher encryption context for encryption, provided a key and cipher parameters.
 \param ctx An allocated stream cipher encryption context.
 \param key A buffer containing the key to use for encryption.
 \param keySize The size, in bytes, of the encryption key.
 \param cipherParams This points to specific stream cipher parameters, set to zero for default behavior.
 \return Returns \c ORDO_ESUCCESS on success, and a negative value on error. */
int encStreamCipherInit(ENC_STREAM_CIPHER_CONTEXT* ctx, void* key, size_t keySize, void* cipherParams);

/*! This function encrypts or decrypts a buffer of a given length using the provided stream cipher encryption context.
 \param ctx The block cipher encryption context to use. This context must have been allocated and initialized.
 \param inout The plaintext or ciphertext buffer.
 \param len Number of bytes to read from the \c inout buffer.
 \remark See \c ordoEncryptStream() for remarks about output buffer size. */
void encStreamCipherUpdate(ENC_STREAM_CIPHER_CONTEXT* ctx, unsigned char* inout, size_t len);

/*! This function frees (deallocates) an initialized stream cipher encryption context.
 \param ctx The stream cipher encryption context to be freed. This context needs to at least have been allocated.
 \remark Once this function returns, the passed context may no longer be used anywhere and sensitive information will
 be wiped. Do not call this function if \c encStreamCipherCreate() failed. */
void encStreamCipherFree(ENC_STREAM_CIPHER_CONTEXT* ctx);

#endif
