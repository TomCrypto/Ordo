/**
 * @file cbc.h
 * Contains the CBC encryption mode interface.
 *
 * Header usage mode: External.
 *
 * @see cbc.c
 */

#ifndef cbc_h
#define cbc_h

#include "encrypt.h"

/*! This is extra context space required by the CBC mode to store temporary incomplete data buffers.*/
typedef struct CBC_RESERVED
{
	/*! The temporary block, the size of the primitive's block size. */
	unsigned char* block;
	/*! The amount of bytes of plaintext or ciphertext currently in the temporary block. */
	size_t available;
} CBC_RESERVED;

/*! This structure describes a symmetric encryption context for the CBC mode. */
typedef struct CBC_ENCRYPT_CONTEXT
{
	/*! The primitive to use. */
	CIPHER_PRIMITIVE* primitive;
	/*! The mode of operation to use (this is set to the CBC mode). */
	ENCRYPT_MODE* mode;
	/*! Points to the key material. */
	void* key;
	/*! Unused field (CBC uses no initialization vector). */
	void* iv;
	/*! Whether to encrypt or decrypt (true = encryption). */
	int direction;
	/*! Whether padding is enabled or not. */
	int padding;
	/*! Reserved space for the CBC mode of operation. */
	CBC_RESERVED* reserved;
} CBC_ENCRYPT_CONTEXT;

void CBC_Create(CBC_ENCRYPT_CONTEXT* ctx);

int CBC_Init(CBC_ENCRYPT_CONTEXT* ctx, void* key, size_t keySize, void* tweak, void* iv);

void CBC_EncryptUpdate(CBC_ENCRYPT_CONTEXT* ctx, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen);

void CBC_DecryptUpdate(CBC_ENCRYPT_CONTEXT* ctx, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen);

int CBC_EncryptFinal(CBC_ENCRYPT_CONTEXT* ctx, unsigned char* out, size_t* outlen);

int CBC_DecryptFinal(CBC_ENCRYPT_CONTEXT* ctx, unsigned char* out, size_t* outlen);

void CBC_Free(CBC_ENCRYPT_CONTEXT* ctx);

void CBC_SetMode(ENCRYPT_MODE* mode);

#endif
