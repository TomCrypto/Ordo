/**
 * @file ecb.h
 * Contains the ECB encryption mode interface.
 *
 * Header usage mode: External.
 *
 * @see ecb.c
 */

#ifndef ecb_h
#define ecb_h

#include "encrypt.h"

/*! This is extra context space required by the ECB mode to store temporary incomplete data buffers.*/
typedef struct ECB_RESERVED
{
	/*! The temporary block, the size of the primitive's block size. */
	unsigned char* block;
	/*! The amount of bytes of plaintext or ciphertext currently in the temporary block. */
	size_t available;
} ECB_RESERVED;

/*! This structure describes a symmetric encryption context for the ECB mode. */
typedef struct ECB_ENCRYPT_CONTEXT
{
	/*! The primitive to use. */
	CIPHER_PRIMITIVE* primitive;
	/*! The mode of operation to use (this is set to the ECB mode). */
	ENCRYPT_MODE* mode;
	/*! Points to the key material. */
	void* key;
	/*! Unused field (ECB uses no initialization vector). */
	void* iv;
	/*! Whether to encrypt or decrypt (true = encryption). */
	int direction;
	/*! Whether padding is enabled or not. */
	int padding;
	/*! Reserved space for the ECB mode of operation. */
	ECB_RESERVED* reserved;
} ECB_ENCRYPT_CONTEXT;

void ECB_Create(ECB_ENCRYPT_CONTEXT* ctx);

int ECB_Init(ECB_ENCRYPT_CONTEXT* ctx, void* key, size_t keySize, void* tweak, void* iv);

void ECB_EncryptUpdate(ECB_ENCRYPT_CONTEXT* ctx, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen);

void ECB_DecryptUpdate(ECB_ENCRYPT_CONTEXT* ctx, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen);

int ECB_EncryptFinal(ECB_ENCRYPT_CONTEXT* ctx, unsigned char* out, size_t* outlen);

int ECB_DecryptFinal(ECB_ENCRYPT_CONTEXT* ctx, unsigned char* out, size_t* outlen);

void ECB_Free(ECB_ENCRYPT_CONTEXT* ctx);

void ECB_SetMode(ENCRYPT_MODE* mode);

#endif
