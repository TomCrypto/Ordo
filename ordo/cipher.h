/*! \file */

#ifndef cipher_h
#define cipher_h

/* Standard includes. */
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

/* Library dependencies. */
#include "securemem.h"
#include "environment.h"

/* Yes, well, stdbool.h doesn't exist under VS2010 for some reason. */
typedef int bool;
#define false 0
#define true 1

/*! Prototype for key size checking, which returns true if the passed key size is acceptable, and false otherwise. */
typedef bool (*KEYSIZECHECK)(size_t);

/*! Prototype for a primitive key schedule function, taking as an input a key, key size, a tweak and writes the prepared key in the last argument. */
typedef bool (* KEYSCHEDULE)(void*, size_t, void*, void*);

/*! Prototype for a primitive's permutation function, taking as an input a block and key. */
typedef void (* PERMUTATION)(void*, void*);

/*! This structure defines a symmetric cipher primitive. */
typedef struct CIPHER_PRIMITIVE
{
	/*! The key size, in bytes, this includes all key material such as key-derived substitution boxes. */
	size_t szKey;
	/*! The block size, in bytes. */
	size_t szBlock;
	/*! The tweak size, in bytes. */
	size_t szTweak;
	/*! Points to the key size verification function. */
	KEYSIZECHECK fKeySizeCheck;
	/*! Points to the primitive's permutation function. */
	PERMUTATION fPermutation;
	/*! Points to the primitive's inverse permutation function. */
	PERMUTATION fInverse;
	/*! Points to the primitive's key schedule. */
	KEYSCHEDULE fKeySchedule;
	/*! The primitive's name. */
	char* name;
} CIPHER_PRIMITIVE;

/*! This structure describes a symmetric cipher context. */
typedef struct CIPHER_CONTEXT
{
	/*! The primitive to use. */
	struct CIPHER_PRIMITIVE* primitive;
	/*! The mode of operation to use. */
	struct CIPHER_MODE* mode;
	/*! Points to the key material. */
	void* key;
	/*! Points to the initialization vector. */
	void* iv;
	/*! Scratch space for the mode of operation. */
	void* block;
	/*! Scratch space index. */
	size_t blockSize;
} CIPHER_CONTEXT;

/*! This is the prototype for a cipher mode of operation initialization function, taking as an
    input a cipher context, a key buffer, a key size, a tweak and an initialization vector. */
typedef bool (* INI_OP)(CIPHER_CONTEXT*, void*, size_t, void*, void*);

/*! This is the prototype for a cipher mode of operation encryption/decryption function, taking
    as an input a cipher context, a buffer, a buffer size and a flag indicating whether padding
	should be applied (this flag is ignored on streaming modes of operation). */
typedef bool (* ENC_OP)(CIPHER_CONTEXT*, unsigned char*, size_t*, bool);

/*! This is the prototype for a cipher mode of operation finalization function, taking as an input a cipher context. */
typedef void (* FIN_OP)(CIPHER_CONTEXT*);

/*! This structure defines a mode of operation. */
typedef struct CIPHER_MODE
{
	/*! Points to the mode of operation's initialization function. */
	INI_OP fInit;
	/*! Points to the mode of operation's encryption function. */
	ENC_OP fEncrypt;
	/*! Points to the mode of operation's decryption function. */
	ENC_OP fDecrypt;
	/*! Points to the mode of operation's finalization function. */
	FIN_OP fFinal;
	/*! The mode of operation's name. */
	char* name;
} CIPHER_MODE;

/*! This function initializes an unallocated cipher context with the given parameters.
 \param ctx This will contain the initialized context (if the function succeeds)
 \param primitive This must point to the cryptographic primitive to be used
 \param mode This must point to the cryptographic mode of operation to be used
 \param key This must point to a buffer containing the raw key
 \param keySize This represents the length, in bytes, of the key buffer
 \param tweak This points to the tweak used in the cipher (this is an optional argument)
 \param iv This points to the initialization vector (this may be zero if the mode does not use an IV)
 \return Returns true on success, false on failure. Possible failure causes include invalid key size for the selected primitive, a missing IV, an invalid primitive or mode. */
bool cipherInit(CIPHER_CONTEXT** ctx, CIPHER_PRIMITIVE* primitive, CIPHER_MODE* mode, void* key, size_t keySize, void* tweak, void* iv);

/*! This function encrypts a buffer of a given length using the provided context.
 \param ctx This must contain a previously initialized cipher context.
 \param buffer This points to a buffer to be encrypted.
 \param size This contains the size of the buffer to be encrypted.
 \param final Whether this is the last buffer to be encrypted before padding.
 \param decrypt Whether to encrypt or decrypt the buffer.
 \return Returns true on success, false on failure.
 \remark If the selected mode of operation is a streaming mode, such as CTR or OFB, the final parameter is ignored. Otherwise, if the buffer is being encrypted, it must have
 enough memory allocated such that it can accomodate data of size multiple of the primitive's block size, and final specifies whether padding is applied or not. If final is
 false, then the buffer effective size (passed in size) must be a multiple of the primitive's block size. If the buffer is being decrypted, and final is true, then the buffer
 will be zero-filled at the location where padding was applied.
 \remark After the function returns, size contains the amount of plaintext or ciphertext produced. If the selected mode of operation is a streaming mode, it remains unchanged.
  Otherwise, it will contain the ciphertext size (this includes padding) or the plaintext size (this excludes padding). */
bool cipherUpdate(CIPHER_CONTEXT* ctx, unsigned char* buffer, size_t* size, bool final, bool decrypt);

/*! This function securely finalizes and deallocates a cipher context.
 \param ctx This must contain a previously initialized cipher context.
 \remark Once this function returns, the passed context may no longer be used in any cipher function. */
void cipherFinal(CIPHER_CONTEXT* ctx);

/*! This convenience function encrypts a buffer of a given length with the provided parameters.
 \param buffer This points to a buffer to be encrypted.
 \param size This contains the size of the buffer to be encrypted.
 \param primitive This must point to the cryptographic primitive to be used
 \param mode This must point to the cryptographic mode of operation to be used
 \param key This must point to a buffer containing the raw key
 \param keySize This represents the length, in bytes, of the key buffer
 \param tweak This points to the tweak used in the cipher (this is an optional argument)
 \param iv This points to the initialization vector (this may be zero if the mode does not use an IV)
 \return Returns true on success, false on failure. 
 \remark If the selected mode is a block mode, padding is automatically applied and the buffer should have enough space to accomodate it. */
bool cipherEncrypt(unsigned char* buffer, size_t* size, CIPHER_PRIMITIVE* primitive, CIPHER_MODE* mode, void* key, size_t keySize, void* tweak, void* iv);

/*! This convenience function decrypts a buffer of a given length with the provided parameters.
 \param buffer This points to a buffer to be encrypted.
 \param size This contains the size of the buffer to be encrypted.
 \param primitive This must point to the cryptographic primitive to be used
 \param mode This must point to the cryptographic mode of operation to be used
 \param key This must point to a buffer containing the raw key
 \param keySize This represents the length, in bytes, of the key buffer
 \param tweak This points to the tweak used in the cipher (this is an optional argument)
 \param iv This points to the initialization vector (this may be zero if the mode does not use an IV)
 \return Returns true on success, false on failure. 
 \remark If the selected mode is a block mode, padding is automatically handled and padding data will be set to zero. */
bool cipherDecrypt(unsigned char* buffer, size_t* size, CIPHER_PRIMITIVE* primitive, CIPHER_MODE* mode, void* key, size_t keySize, void* tweak, void* iv);

/* Primitive list. */
#include "identity.h"
#include "xortoy.h"
#include "threefish.h"

/* Mode of operation list. */
#include "ecb.h"
#include "ctr.h"
#include "ofb.h"

/*! The Identity primitive. */
CIPHER_PRIMITIVE* IDENTITY;
/*! The XORToy primitive. */
CIPHER_PRIMITIVE* XORTOY;
/*! The Threefish-256 primitive. */
CIPHER_PRIMITIVE* THREEFISH;

/*! The ECB (Electronic CodeBook) mode of operation. */
CIPHER_MODE* ECB;
/*! The CTR (Counter) mode of operation. */
CIPHER_MODE* CTR;
/*! The OFB (Output FeedBack) mode of operation. */
CIPHER_MODE* OFB;

/*! Initializes all primitives. */
void loadPrimitives();

/*! Initializes all modes of operation. */
void loadModes();

#endif