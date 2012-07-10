/*! \file */

#ifndef encrypt_h
#define encrypt_h

/* Library dependencies. */
#include "primitives.h"
#include "ordotypes.h"

/*! This structure describes a symmetric encryption context. */
typedef struct ENCRYPT_CONTEXT
{
	/*! The primitive to use. */
	CIPHER_PRIMITIVE* primitive;
	/*! The mode of operation to use. */
	struct ENCRYPT_MODE* mode;
	/*! Points to the key material. */
	void* key;
	/*! Points to the initialization vector. */
	void* iv;
	/*! Reserved space for the mode of operation. */
	void* scratch;
	/* Whether to encrypt or decrypt. */
	bool direction;
} ENCRYPT_CONTEXT;

/*! This is the prototype for a cipher mode of operation allocation function, which simply allocates context memory. */
typedef void (* CREATE_FUNC)(ENCRYPT_CONTEXT*);

/*! This is the prototype for a cipher mode of operation initialization function, taking as an
    input a cipher context, a key buffer, a key size, a tweak and an initialization vector. */
typedef bool (* INIT_FUNC)(ENCRYPT_CONTEXT*, void*, size_t, void*, void*);

/*! This is the prototype for a cipher mode of operation encryption/decryption function, taking
    as an input a cipher context, a buffer, a buffer size and a flag indicating whether padding
	should be applied (this flag is ignored on streaming modes of operation). */
typedef bool (* UPDATE_FUNC)(ENCRYPT_CONTEXT*, unsigned char*, size_t, unsigned char*, size_t*);

/*! This is the prototype for a cipher mode of operation finalization function, taking as an input a cipher context. */
typedef bool (* FINAL_FUNC)(ENCRYPT_CONTEXT*, unsigned char*, size_t*);

/*! This is the prototype for a cipher mode of operation deallocation function, which simply deallocates context memory. */
typedef void (* FREE_FUNC)(ENCRYPT_CONTEXT*);


/*! This structure defines a mode of operation. */
typedef struct ENCRYPT_MODE
{
	/*! Points to the mode of operation's allocation function. */
	CREATE_FUNC fCreate;
	/*! Points to the mode of operation's initialization function. */
	INIT_FUNC fInit;
	/*! Points to the mode of operation's encryption function. */
	UPDATE_FUNC fEncryptUpdate;
	/*! Points to the mode of operation's decryption function. */
	UPDATE_FUNC fDecryptUpdate;
	/*! Points to the mode of operation's finalization function for encryption. */
	FINAL_FUNC fEncryptFinal;
	/*! Points to the mode of operation's finalization function for decryption. */
	FINAL_FUNC fDecryptFinal;
	/*! Points to the mode of operation's deallocation function. */
	FREE_FUNC fFree;
	/*! The mode of operation's name. */
	char* name;
} ENCRYPT_MODE;

/*! This function returns an initialized encryption context using a specific primitive and mode of operation.
 \param primitive This must point to the cryptographic primitive to be used
 \param mode This must point to the cryptographic mode of operation to be used
 \param direction This describes the direction of encryption, set to true for encryption and false for decryption.
 \return Returns the initialized encryption context. */
ENCRYPT_CONTEXT* encryptCreate(CIPHER_PRIMITIVE* primitive, ENCRYPT_MODE* mode, bool direction);

/*! This function prepares an encryption context to be used for encryption, provided a key, tweak and initialization vector.
 \param ctx The encryption context to use
 \param key This must point to a buffer containing the raw key
 \param keySize This represents the length, in bytes, of the key buffer
 \param tweak This points to the tweak used in the cipher (this is an optional argument)
 \param iv This points to the initialization vector (this may be zero if the mode does not use an IV)
 \return Returns true on success, false on failure. Possible failure causes include invalid key size for the selected primitive, a missing IV. */
bool encryptInit(ENCRYPT_CONTEXT* ctx, void* key, size_t keySize, void* tweak, void* iv);

/*! This function encrypts or decrypts a buffer of a given length using the provided context.
 \param ctx The encryption context to use
 \param in This points to a buffer containing plaintext (or ciphertext)
 \param inlen This contains the size of the in buffer, in bytes
 \param out This points to a buffer which will contain the plaintext (or ciphertext)
 \param outlen This will contain the size of the out buffer, in bytes
 \param decrypt Whether to encrypt or decrypt the buffer.
 \return Returns true on success, false on failure. */
bool encryptUpdate(ENCRYPT_CONTEXT* ctx, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen);

/*! This function finalizes an encryption context, and returns any leftover plaintext or ciphertext.
 \param ctx The encryption context to use
 \param out This points to a buffer which will contain the plaintext (or ciphertext)
 \param outlen This will contain the size of the out buffer, in bytes
 \remark Once this function returns, the passed context can no longer be used in encryptUpdate . */
bool encryptFinal(ENCRYPT_CONTEXT* ctx, unsigned char* out, size_t* outlen);

/*! This function frees an initialized encryption context.
 \param ctx The encryption context to be freed.
 \remark Once this function returns, the passed context may no longer be used for encryption. */
void encryptFree(ENCRYPT_CONTEXT* ctx);

/*! The ECB (Electronic CodeBook) mode of operation. */
ENCRYPT_MODE* ECB;
/*! The CTR (CounTeR) mode of operation. */
ENCRYPT_MODE* CTR;
/*! The OFB (Output FeedBack) mode of operation. */
ENCRYPT_MODE* OFB;

/*! Loads all encryption modes of operation. */
void loadEncryptModes();

/*! Unloads all encryption modes of operation. */
void unloadEncryptModes();

#endif