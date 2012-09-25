#ifndef ENC_BLOCK_H
#define ENC_BLOCK_H

/**
 * @file enc_block.h
 *
 * \brief Block cipher symmetric encryption.
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
 *
 * @see enc_block.c
 */

/* Library dependencies. */
#include <primitives/primitives.h>
#include <common/ordotypes.h>

/* Macro to initialize a block cipher mode of operation. */
#define MAKE_BLOCK_CIPHER_MODE(m, c, i, eu, du, ef, df, f, n)                                                         \
    m->fCreate = (BLOCK_CIPHER_MODE_CREATE)c;                                                                         \
    m->fInit = (BLOCK_CIPHER_MODE_INIT)i;                                                                             \
    m->fEncryptUpdate = (BLOCK_CIPHER_MODE_UPDATE)eu;                                                                 \
    m->fDecryptUpdate = (BLOCK_CIPHER_MODE_UPDATE)du;                                                                 \
    m->fEncryptFinal = (BLOCK_CIPHER_MODE_FINAL)ef;                                                                   \
    m->fDecryptFinal = (BLOCK_CIPHER_MODE_FINAL)df;                                                                   \
    m->fFree = (BLOCK_CIPHER_MODE_FREE)f;                                                                             \
    m->name = n;

/*! Returns the name of a mode of operation object. */
#define blockCipherModeName(m) (m->name)

/*! \brief Block cipher mode of operation context.
 *
 * This structure describes a block cipher mode of operation context. It is used by encryption modes of operation to
 * maintain their state across function calls. It should never be modified outside of these functions. */
typedef struct BLOCK_CIPHER_MODE_CONTEXT
{
    /*! The block cipher mode of operation to use. */
    struct BLOCK_CIPHER_MODE* mode;
    /*! The mode of operation's low-level context. */
    void* ctx;
    /*! Whether to encrypt or decrypt (1 corresponds to encryption). */
    int direction;
} BLOCK_CIPHER_MODE_CONTEXT;

/* Block cipher mode of operation interface function prototypes. */
typedef BLOCK_CIPHER_MODE_CONTEXT* (* BLOCK_CIPHER_MODE_CREATE)(BLOCK_CIPHER_CONTEXT*);
typedef int (* BLOCK_CIPHER_MODE_INIT)(BLOCK_CIPHER_MODE_CONTEXT*, BLOCK_CIPHER_CONTEXT*, void*, void*);
typedef void (* BLOCK_CIPHER_MODE_UPDATE)(BLOCK_CIPHER_MODE_CONTEXT*, BLOCK_CIPHER_CONTEXT*,
                                          unsigned char*, size_t, unsigned char*, size_t*);
typedef int (* BLOCK_CIPHER_MODE_FINAL)(BLOCK_CIPHER_MODE_CONTEXT*, BLOCK_CIPHER_CONTEXT*, unsigned char*, size_t*);
typedef void (* BLOCK_CIPHER_MODE_FREE)(BLOCK_CIPHER_MODE_CONTEXT*, BLOCK_CIPHER_CONTEXT*);

/*! \brief Block cipher mode of operation object.
 *
 * This represents a block cipher mode of operation object. */
typedef struct BLOCK_CIPHER_MODE
{
    BLOCK_CIPHER_MODE_CREATE fCreate;
    BLOCK_CIPHER_MODE_INIT fInit;
    BLOCK_CIPHER_MODE_UPDATE fEncryptUpdate;
    BLOCK_CIPHER_MODE_UPDATE fDecryptUpdate;
    BLOCK_CIPHER_MODE_FINAL fEncryptFinal;
    BLOCK_CIPHER_MODE_FINAL fDecryptFinal;
    BLOCK_CIPHER_MODE_FREE fFree;
    char* name;
} BLOCK_CIPHER_MODE;

/*! \brief Block cipher symmetric encryption context.
 *
 * This structure describes a high-level symmetric encryption context. It contains the context of both the block cipher
 * and the mode of operation, and should be regarded as an opaque container. */
typedef struct ENC_BLOCK_CIPHER_CONTEXT
{
    /*! The block cipher context. */
    BLOCK_CIPHER_CONTEXT* cipherCtx;
    /*! The mode of operation context. */
    BLOCK_CIPHER_MODE_CONTEXT* modeCtx;
} ENC_BLOCK_CIPHER_CONTEXT;

/*! Loads all encryption modes of operation. This must be called before you may use \c ECB(), \c CBC(), etc... or the
 * helper functions \c getBlockCipherModeByName() and \c getBlockCipherModeByID(). */
void encryptLoad();

/*! The ECB (Electronic CodeBook) mode of operation. */
BLOCK_CIPHER_MODE* ECB();
/*! The CBC (Ciphertext Block Chaining) mode of operation. */
BLOCK_CIPHER_MODE* CBC();
/*! The CTR (CounTeR) mode of operation. */
BLOCK_CIPHER_MODE* CTR();
/*! The CFB (Cipher FeedBack) mode of operation. */
BLOCK_CIPHER_MODE* CFB();
/*! The OFB (Output FeedBack) mode of operation. */
BLOCK_CIPHER_MODE* OFB();

/*! Gets a block cipher mode of operation object from a name. */
BLOCK_CIPHER_MODE* getBlockCipherModeByName(char* name);

/*! Gets a block cipher mode of operation object from an ID. */
BLOCK_CIPHER_MODE* getBlockCipherModeByID(size_t ID);

/*! This function returns an allocated block cipher mode of operation context using a specific mode of operation and
 * an initialized block cipher context.
 \param mode The mode of operation object to be used.
 \param cipherCtx The block cipher context to use.
 \return Returns the allocated mode of operation context, or 0 if an error occurred. */
BLOCK_CIPHER_MODE_CONTEXT* blockCipherModeCreate(BLOCK_CIPHER_MODE* mode, BLOCK_CIPHER_CONTEXT* cipherCtx);

/*! This function initializes a block cipher mode of operation context for encryption, provided an initialization
 * vector and mode-specific parameters.
 \param modeCtx An allocated mode of operation context.
 \param cipherCtx The block cipher context.
 \param iv A buffer containing t he initialization vector. Note the length of the initialization vector is known to be
 the same as the block size of the chosen block cipher.
 \param modeParams This contains mode-specific parameters, set to zero for default behaviour.
 \param direction This represents the direction of encryption, set to 1 for encryption and 0 for decryption.
 \return Returns \c ORDO_ESUCCESS on success, and a negative value on error.
 \remark The initialization vector may be zero, if the mode of operation does not require one. */
int blockCipherModeInit(BLOCK_CIPHER_MODE_CONTEXT* modeCtx, BLOCK_CIPHER_CONTEXT* cipherCtx,
                        void* iv, void* modeParams, int direction);

/*! This function encrypts or decrypts a buffer of a given length using the provided block cipher and mode of operation
 * contexts.
 \param modeCtx The mode of operation context to use. This context must have been allocated and initialized.
 \param cipherCtx The block cipher context to use.
 \param in This points to a buffer containing plaintext (or ciphertext).
 \param inlen This contains the size of the \c in buffer, in bytes.
 \param out This points to a buffer which will contain the output of the function.
 \param outlen This points to a variable which will contain the number of bytes written to \c out.
 \remark The out buffer should have enough space to store the entire resulting ciphertext or plaintext If padding
 is not used or disabled, \c out may be exactly as large as \c in, but if padding is enabled, \c out needs to be sized
 appropriately either up to the nearest block size ( \c outlen strictly greater than \c inlen) for encryption, either
 down to the nearest block size for decryption ( \c outlen strictly less than \c inlen) for decryption.
 \remark By design, the block cipher symmetric encryption API considers every buffer given to this function between a
 \c blockEncryptModeInit() and a \c blockEncryptModeFinal() call to be part of one large buffer, hence care must be
 taken to respect this assumption. */
void blockCipherModeUpdate(BLOCK_CIPHER_MODE_CONTEXT* modeCtx, BLOCK_CIPHER_CONTEXT* cipherCtx,
                           unsigned char* in, size_t inlen,
                           unsigned char* out, size_t* outlen);

/*! This function finalizes a block cipher mode of operation context, and will process and return any leftover
 * plaintext or ciphertext.
 \param modeCtx The mode of operation context to use. This context must have been allocated and initialized.
 \param cipherCtx The block cipher context to use.
 \param out This points to a buffer which will contain any remaining plaintext (or ciphertext).
 \param outlen This points to a variable which will contain the number of bytes written to \c out.
 \return Returns \c ORDO_ESUCCESS on success, and a negative value on error.
 \remark Once this function returns, the passed context can no longer be used for encryption or decryption.
 \remark If padding is disabled, and the mode of operation is a block mode, this function will fail with \c E_LEFTOVER
 if there is any unprocessed data left in the context. \n
 If the mode of operation used does not use padding, then this function returns no additional data. \n
 If padding is enabled, \c out should have space to hold at most one additional block of data (block cipher's block
 size), and at least one byte of data. It is possible to calculate in advance the amount of data returned. \n\n
 You may pass 0 in \c outlen if it makes sense, e.g. if you are using a mode of operation which does not use padding,
 no final data will ever be returned by design. In such situations, the implementation will ignore \c outlen if you
 pass zero, and will set its value to zero if it is specified. Consult the documentation of the appropriate mode to
 learn what it does. */
int blockCipherModeFinal(BLOCK_CIPHER_MODE_CONTEXT* modeCtx, BLOCK_CIPHER_CONTEXT* cipherCtx,
                         unsigned char* out, size_t* outlen);

/*! This function frees (deallocates) an initialized block cipher mode of operation context.
 \param modeCtx The encryption context to be freed. This context needs to at least have been allocated.
 \param cipherCtx The block cipher context.
 \remark Once this function returns, the passed context may no longer be used anywhere and sensitive information will
 be wiped. Do not call this function if \c blockEncryptModeCreate() failed, as the latter correctly frees dangling
 context buffers in case of error. \n\n
 This function does not free the block cipher context, which can be reused again in another mode of operation. */
void blockCipherModeFree(BLOCK_CIPHER_MODE_CONTEXT* modeCtx, BLOCK_CIPHER_CONTEXT* cipherCtx);

/*! This function returns an allocated block cipher encryption context using a specific block cipher and mode of
 * operation.
 \param cipher The block cipher object to be used.
 \param mode The mode of operation object to be used.
 \return Returns the allocated block cipher encryption context, or 0 if an error occurred. */
ENC_BLOCK_CIPHER_CONTEXT* encBlockCipherCreate(BLOCK_CIPHER* cipher, BLOCK_CIPHER_MODE* mode);

/*! This function initializes a block cipher encryption context for encryption, provided a key, initialization vector,
 * and cipher/mode-specific parameters.
 \param ctx An allocated block cipher encryption context.
 \param key A buffer containing the key to use for encryption.
 \param keySize The size, in bytes, of the encryption key.
 \param iv This points to the initialization vector.
 \param cipherParams This points to specific cipher parameters, set to zero for default behavior.
 \param modeParams This points to specific mode of operation parameters, set to zero for default behavior.
 \param direction This represents the direction of encryption, set to 1 for encryption and 0 for decryption.
 \return Returns \c ORDO_ESUCCESS on success, and a negative value on error.
 \remark The initialization vector may be zero, if the mode of operation does not require one. */
int encBlockCipherInit(ENC_BLOCK_CIPHER_CONTEXT* ctx, void* key, size_t keySize, void* iv,
                       void* cipherParams, void* modeParams, int direction);

/*! This function encrypts or decrypts a buffer of a given length using the provided block cipher encryption context.
 \param ctx The block cipher encryption context to use. This context must have been allocated and initialized.
 \param in This points to a buffer containing plaintext (or ciphertext).
 \param inlen This contains the size of the \c in buffer, in bytes.
 \param out This points to a buffer which will contain the plaintext (or ciphertext).
 \param outlen This points to a variable which will contain the number of bytes written to \c out.
 \remark See \c blockEncryptModeUpdate() for remarks about output buffer size. */
void encBlockCipherUpdate(ENC_BLOCK_CIPHER_CONTEXT* ctx,
                          unsigned char* in, size_t inlen,
                          unsigned char* out, size_t* outlen);

/*! This function finalizes a block cipher encryption context, and will process and return any leftover plaintext or
 * ciphertext.
 \param ctx The block cipher encryption context to use. This context must have been allocated and initialized.
 \param out This points to a buffer which will contain any remaining plaintext (or ciphertext).
 \param outlen This points to a variable which will contain the number of bytes written to \c out.
 \return Returns \c ORDO_ESUCCESS on success, and a negative value on error.
 \remark Once this function returns, the passed context can no longer be used for encryption or decryption.
 \remark See \c blockEncryptModeFinal() for remarks. */
int encBlockCipherFinal(ENC_BLOCK_CIPHER_CONTEXT* ctx, unsigned char* out, size_t* outlen);

/*! This function frees (deallocates) an initialized block cipher encryption context.
 \param ctx The block cipher encryption context to be freed. This context needs to at least have been allocated.
 \remark Once this function returns, the passed context may no longer be used anywhere and sensitive information will
 be wiped. Do not call this function if \c blockEncryptCreate() failed, as the latter correctly frees dangling context
 buffers in case of error. */
void encBlockCipherFree(ENC_BLOCK_CIPHER_CONTEXT* ctx);

#endif
