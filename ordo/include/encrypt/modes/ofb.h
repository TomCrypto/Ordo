#ifndef ofb_h
#define ofb_h

/**
 * @file ofb.h
 * Contains the OFB encryption mode interface.
 *
 * Header usage mode: External.
 *
 * @see ofb.c
 */

#include <encrypt/encrypt.h>

void OFB_Create(ENCRYPT_MODE_CONTEXT*  mode, CIPHER_PRIMITIVE_CONTEXT* cipher);

int OFB_Init(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, void* iv, void* params);

void OFB_Update(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen);

int OFB_Final(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* out, size_t* outlen);

void OFB_Free(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher);

void OFB_SetMode(ENCRYPT_MODE* mode);

#endif
