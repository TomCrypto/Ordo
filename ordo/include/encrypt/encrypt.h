#ifndef encrypt_h
#define encrypt_h

/**
 * @file encrypt.h
 *
 * \brief Symmetric encryption interface.
 *
 * Exposes the Ordo symmetric encryption interface, to encrypt plaintext and decrypt ciphertext with different ciphers and modes of operation.
 * Note it is always possible to skip this API and directly use the lower-level functions available in the individual cipher and mode of operation
 * headers, but this interface abstracts away some of the more boilerplate details and so should be preferred.
 *
 * If you wish to use the lower level API, you will need to manage your cipher primitive contexts yourself, which can give more flexibility in
 * some cases but is usually unnecessary.
 *
 * The padding algorithm is PKCS7 (RFC 5652), which appends N bytes of value N, where N is the number of padding
 * bytes required (between 1 and the cipher's block size in bytes).
 *
 * @see encrypt.c
 */

/* Library dependencies. */
#include <primitives/primitives.h>
#include <common/ordotypes.h>

/* Useful macro to initialize a mode of operation. */
#define ENCRYPT_MAKEMODE(m, c, i, eu, du, ef, df, f, n) m->fCreate = (CREATE_FUNC)c; m->fInit = (INIT_FUNC)i; m->fEncryptUpdate = (UPDATE_FUNC)eu; m->fDecryptUpdate = (UPDATE_FUNC)du; m->fEncryptFinal = (FINAL_FUNC)ef; m->fDecryptFinal = (FINAL_FUNC)df; m->fFree = (FREE_FUNC)f; m->name = n;

/*! Returns the name of a mode of operation object. */
#define modeName(m) (m->name)

/*! \brief Mode of operation context.
 *
 * This structure describes a mode of operation context. It is used by
 * encryption modes of operation to maintain their state across function
 * calls. It should never be modified outside of these functions. */
typedef struct ENCRYPT_MODE_CONTEXT
{
    /*! The mode of operation to use. */
    struct ENCRYPT_MODE* mode;
    /*! The encryption mode low-level context. */
    void* ctx;
    /*! Whether to encrypt or decrypt (1 corresponds to encryption). */
    int direction;
} ENCRYPT_MODE_CONTEXT;

/* This is the prototype for a cipher mode of operation allocation function, which simply allocates context memory. */
typedef void (* CREATE_FUNC)(ENCRYPT_MODE_CONTEXT*, CIPHER_PRIMITIVE_CONTEXT*);

/* This is the prototype for a cipher mode of operation initialization function, taking as an
    input a cipher context, a key buffer, a key size, a tweak and an initialization vector. */
typedef int (* INIT_FUNC)(ENCRYPT_MODE_CONTEXT*, CIPHER_PRIMITIVE_CONTEXT*, void*, void*);

/* This is the prototype for a cipher mode of operation encryption/decryption function, taking
    as an input a cipher context, a buffer, a buffer size and a flag indicating whether padding
	should be applied (this flag is ignored on streaming modes of operation). */
typedef void (* UPDATE_FUNC)(ENCRYPT_MODE_CONTEXT*, CIPHER_PRIMITIVE_CONTEXT*, unsigned char*, size_t, unsigned char*, size_t*);

/* This is the prototype for a cipher mode of operation finalization function, taking as an input a cipher context. */
typedef int (* FINAL_FUNC)(ENCRYPT_MODE_CONTEXT*, CIPHER_PRIMITIVE_CONTEXT*, unsigned char*, size_t*);

/* This is the prototype for a cipher mode of operation deallocation function, which simply deallocates context memory. */
typedef void (* FREE_FUNC)(ENCRYPT_MODE_CONTEXT*, CIPHER_PRIMITIVE_CONTEXT*);

/* This structure defines an encryption mode of operation. Encryption modes of operation are separated into two categories: block modes, which process one block of plaintext/ciphertext at a time, and streaming modes
 * which can process data byte-by-byte (bit, actually, but the smallest addressable unit is usually a byte). Block modes require padding to encrypt data that is not a multiple of the primitive's block size, whereas
 * streaming modes do not. Refer to the individual mode of operation's headers to find out in which category they are. */
typedef struct ENCRYPT_MODE
{
    /* Points to the mode of operation's allocation function. */
    CREATE_FUNC fCreate;
    /* Points to the mode of operation's initialization function. */
    INIT_FUNC fInit;
    /* Points to the mode of operation's encryption function. */
    UPDATE_FUNC fEncryptUpdate;
    /* Points to the mode of operation's decryption function. */
    UPDATE_FUNC fDecryptUpdate;
    /* Points to the mode of operation's finalization function for encryption. */
    FINAL_FUNC fEncryptFinal;
    /* Points to the mode of operation's finalization function for decryption. */
    FINAL_FUNC fDecryptFinal;
    /* Points to the mode of operation's deallocation function. */
    FREE_FUNC fFree;
    /* The mode of operation's name. */
    char* name;
} ENCRYPT_MODE;

/*! \brief Symmetric encryption context.
 *
 * This structure describes a high-level symmetric encryption context.
 * It contains the context of both the cipher primitive and the mode
 * of operation, and should be regarded as an opaque container. */
typedef struct ENCRYPTION_CONTEXT
{
    /*! The cipher context. */
    CIPHER_PRIMITIVE_CONTEXT* cipher;
    /*! The mode of operation context. */
    ENCRYPT_MODE_CONTEXT* mode;
} ENCRYPTION_CONTEXT;

/*! Loads all encryption modes of operation. This must be called (or the mode of operation objects must be initialized by some other means) before
 * the ECB, CBC, etc... global variables can be used for encryption or decryption. */
void encryptLoad();

/*! Unloads all encryption modes of operation. After calling this, the ECB, CBC... mode of operation objects may no longer be used. */
void encryptUnload();

/*! The ECB (Electronic CodeBook) mode of operation. */
ENCRYPT_MODE* ECB();
/*! The CBC (Ciphertext Block Chaining) mode of operation. */
ENCRYPT_MODE* CBC();
/*! The CTR (CounTeR) mode of operation. */
ENCRYPT_MODE* CTR();
/*! The CFB (Cipher FeedBack) mode of operation. */
ENCRYPT_MODE* CFB();
/*! The OFB (Output FeedBack) mode of operation. */
ENCRYPT_MODE* OFB();
/*! The STREAM mode of operation (for stream ciphers only). */
ENCRYPT_MODE* STREAM();

/*! Gets an encryption mode object from a name. */
ENCRYPT_MODE* getEncryptMode(char* name);

/*! This function returns an allocated encryption mode context using a specific mode of operation and initialized cipher context.
 \param mode The mode of operation object to be used.
 \param cipher The cipher primitive context to use.
 \return Returns the allocated encryption context, or 0 if an allocation error occurred. */
ENCRYPT_MODE_CONTEXT* encryptModeCreate(ENCRYPT_MODE* mode, CIPHER_PRIMITIVE_CONTEXT* cipher);

/*! This function initializes an encryption mode context for encryption, provided an initialization vector and mode-specific parameters.
 \param ctx An allocated encryption mode context.
 \param cipher The cipher primitive context to use.
 \param iv This points to the initialization vector. Note the length of the initialization vector is known to be
 the same as the block size of the cipher primitive associated with the provided encryption context.
 \param modeParams This contains mode-specific parameters, to enable or disable specific behavior.
 \param direction This represents the direction of encryption, set to 1 for encryption and 0 for decryption.
 \return Returns \c ORDO_ESUCCESS on success, and a negative value on error.
 \remark The initialization vector may be zero, if the mode of operation does not require one. */
int encryptModeInit(ENCRYPT_MODE_CONTEXT* ctx, CIPHER_PRIMITIVE_CONTEXT* cipher, void* iv, void* modeParams, int direction);

/*! This function encrypts or decrypts a buffer of a given length using the provided encryption mode context.
 \param ctx The encryption mode context to use. This context must have been allocated and initialized.
 \param cipher The cipher primitive context to use.
 \param in This points to a buffer containing plaintext (or ciphertext).
 \param inlen This contains the size of the in buffer, in bytes.
 \param out This points to a buffer which will contain the plaintext (or ciphertext).
 \param outlen This points to a variable which will contain the number of bytes written to out.
 \remark The out buffer should have enough space to store the entire resulting ciphertext or plaintext If padding
 is not used or disabled, out may be exactly as large as in, but if padding is enabled, out needs to be sized
 appropriately either up to the nearest cipher block size (outlen strictly greater than inlen) for encryption,
 either down to the nearest cipher block size for decryption (outlen strictly less than inlen) for decryption.
 \remark By design, the symmetric encryption API considers every buffer given to this function between an \c encryptModeInit
 and an \c encryptModeFinal call to be part of one large buffer, hence care must be taken to respect this assumption. */
void encryptModeUpdate(ENCRYPT_MODE_CONTEXT* ctx, CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen);

/*! This function finalizes an encryption mode context, and will process and return any leftover plaintext or ciphertext.
 \param ctx The encryption mode context to use. This context must have been allocated and initialized.
 \param cipher The cipher primitive context to use.
 \param out This points to a buffer which will contain any remaining plaintext (or ciphertext).
 \param outlen This points to a variable which will contain the number of bytes written to out.
 \return Returns \c ORDO_ESUCCESS on success, and a negative value on error.
 \remark Once this function returns, the passed context can no longer be used for encryption or decryption.
 \remark If padding is disabled, and the mode of operation is a block mode, this function will fail if there is any unprocessed data left in the context.
 \remark If padding is disabled, or there is no padding in the mode of operation associated with the encryption context, this function returns no additional data.
 \remark If padding is enabled, out should have space to hold at most one additional block of data (cipher primitive's block size), and at least one byte of data. */
int encryptModeFinal(ENCRYPT_MODE_CONTEXT* ctx, CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* out, size_t* outlen);

/*! This function frees (deallocates) an initialized encryption mode context.
 \param ctx The encryption context to be freed. This context needs to at least have been allocated.
 \param cipher The cipher primitive context to use.
 \remark Once this function returns, the passed context may no longer be used anywhere and sensitive information will be wiped.
 Do not call this function if \c encryptModeCreate failed, as the latter correctly frees dangling context buffers in case of error. */
void encryptModeFree(ENCRYPT_MODE_CONTEXT* ctx, CIPHER_PRIMITIVE_CONTEXT* cipher);

/*! This function returns an allocated encryption context using a specific primitive and mode of operation.
 \param primitive The primitive object to be used.
 \param mode The mode of operation object to be used.
 \return Returns the allocated encryption context, or 0 if an allocation error occurred. */
ENCRYPTION_CONTEXT* encryptCreate(CIPHER_PRIMITIVE* primitive, ENCRYPT_MODE* mode);

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
int encryptInit(ENCRYPTION_CONTEXT* ctx, void* key, size_t keySize, void* iv, void* cipherParams, void* modeParams, int direction);

/*! This function encrypts or decrypts a buffer of a given length using the provided encryption context.
 \param ctx The encryption context to use. This context must have been allocated and initialized.
 \param in This points to a buffer containing plaintext (or ciphertext).
 \param inlen This contains the size of the in buffer, in bytes.
 \param out This points to a buffer which will contain the plaintext (or ciphertext).
 \param outlen This points to a variable which will contain the number of bytes written to out.
 \remark See \c encryptModeUpdate remarks about output buffer size. */
void encryptUpdate(ENCRYPTION_CONTEXT* ctx, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen);

/*! This function finalizes an encryption context, and will process and return any leftover plaintext or ciphertext.
 \param ctx The encryption context to use. This context must have been allocated and initialized.
 \param out This points to a buffer which will contain any remaining plaintext (or ciphertext).
 \param outlen This points to a variable which will contain the number of bytes written to out.
 \return Returns \c ORDO_ESUCCESS on success, and a negative value on error.
 \remark Once this function returns, the passed context can no longer be used for encryption or decryption.
 \remark See \c encryptModeFinal remarks. */
int encryptFinal(ENCRYPTION_CONTEXT* ctx, unsigned char* out, size_t* outlen);

/*! This function frees (deallocates) an initialized encryption context.
 \param ctx The encryption context to be freed. This context needs to at least have been allocated.
 \remark Once this function returns, the passed context may no longer be used anywhere and sensitive information will be wiped.
 Do not call this function if \c encryptCreate failed, as the latter correctly frees dangling context buffers in case of error. */
void encryptFree(ENCRYPTION_CONTEXT* ctx);

#endif
