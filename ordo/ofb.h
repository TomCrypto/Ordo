/**
 * @file ofb.h
 * Contains the OFB encryption mode interface.
 *
 * Header usage mode: External.
 *
 * @see ofb.c
 */

#ifndef ofb_h
#define ofb_h

#include "encrypt.h"

/*! This is extra context space required by the OFB mode to store the amount of state not used.*/
typedef struct OFB_RESERVED
{
	/*! The amount of bytes of unused state remaining before the state is to be renewed. */
	size_t remaining;
} OFB_RESERVED;

/*! This structure describes a symmetric encryption context for the OFB mode. */
typedef struct OFB_ENCRYPT_CONTEXT
{
	/*! The primitive to use. */
	CIPHER_PRIMITIVE* primitive;
	/*! The mode of operation to use (this is set to the OFB mode). */
	struct ENCRYPT_MODE* mode;
	/*! Points to the key material. */
	void* key;
	/*! Points to the initialization vector. */
	void* iv;
	/*! Whether to encrypt or decrypt (true = encryption). */
	int direction;
	/*! Whether padding is enabled or not. */
	int padding;
	/*! Reserved space for the OFB mode of operation. */
	OFB_RESERVED* reserved;
} OFB_ENCRYPT_CONTEXT;

void OFB_Create(OFB_ENCRYPT_CONTEXT* ctx);

int OFB_Init(OFB_ENCRYPT_CONTEXT* ctx, void* key, size_t keySize, void* tweak, void* iv);

void OFB_Update(OFB_ENCRYPT_CONTEXT* ctx, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen);

int OFB_Final(OFB_ENCRYPT_CONTEXT* ctx, unsigned char* out, size_t* outlen);

void OFB_Free(OFB_ENCRYPT_CONTEXT* ctx);

void OFB_SetMode(ENCRYPT_MODE* mode);

#endif
