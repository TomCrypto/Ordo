/* Library dependencies. */
#include <primitives/primitives.h>
#include <common/ordotypes.h>

/*! \brief Symmetric encryption context (for stream ciphers).
 *
 * This structure describes a high-level symmetric encryption context.
 * It contains the context of both the cipher primitive and the mode
 * of operation, and should be regarded as an opaque container. */
typedef struct ENC_STREAM_CONTEXT
{
    /*! The cipher context. */
    STREAM_CIPHER_CONTEXT* cipherCtx;
} ENC_STREAM_CONTEXT;

/*! This function returns an allocated encryption context using a specific primitive and mode of operation.
 \param primitive The primitive object to be used.
 \param mode The mode of operation object to be used.
 \return Returns the allocated encryption context, or 0 if an allocation error occurred. */
ENC_STREAM_CONTEXT* enc_stream_create(STREAM_CIPHER* cipher);

/*! This function initializes an encryption context for encryption, provided a key, initialization vector,
 * and cipher/mode-specific parameters.
 \param ctx An allocated encryption context.
 \param key A pointer to a buffer containing the key to use for encryption.
 \param keySize The size, in bytes, of the encryption key.
 \param iv This points to the initialization vector. Note the length of the initialization vector is known to be
 the same as the block size of the cipher primitive associated with the provided encryption context.
 \param cipherParams This points to specific cipher parameters, set to zero for default behavior.
 \param modeParams This points to specific mode of operation parameters, set to zero for default behavior.
 \param direction This represents the direction of encryption, set to 1 for encryption and 0 for decryption.
 \return Returns \c ORDO_ESUCCESS on success, and a negative value on error.
 \remark The initialization vector may be zero, if the mode of operation does not require one. */
int enc_stream_init(ENC_STREAM_CONTEXT* ctx, void* key, size_t keySize, void* cipherParams);

/*! This function encrypts or decrypts a buffer of a given length using the provided encryption context.
 \param ctx The encryption context to use. This context must have been allocated and initialized.
 \param in This points to a buffer containing plaintext (or ciphertext).
 \param inlen This contains the size of the in buffer, in bytes.
 \param out This points to a buffer which will contain the plaintext (or ciphertext).
 \param outlen This points to a variable which will contain the number of bytes written to out.
 \remark See \c blockEncryptModeUpdate remarks about output buffer size. */
void enc_stream_update(ENC_STREAM_CONTEXT* ctx, unsigned char* inout, size_t len);

/*! This function frees (deallocates) an initialized encryption context.
 \param ctx The encryption context to be freed. This context needs to at least have been allocated.
 \remark Once this function returns, the passed context may no longer be used anywhere and sensitive information will be wiped.
 Do not call this function if \c blockEncryptCreate failed, as the latter correctly frees dangling context buffers in case of error. */
void enc_stream_free(ENC_STREAM_CONTEXT* ctx);
