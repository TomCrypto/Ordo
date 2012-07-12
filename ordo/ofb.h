/**
 * @file OFB.h
 * Contains the OFB encryption mode interface.
 * 
 * Header usage mode: External.
 *
 * @see OFB.c
 */

#ifndef ofb_h
#define ofb_h

#include "encrypt.h"

void OFB_Create(ENCRYPT_CONTEXT* ctx);

bool OFB_Init(ENCRYPT_CONTEXT* ctx, void* key, size_t keySize, void* tweak, void* iv);

bool OFB_EncryptUpdate(ENCRYPT_CONTEXT* ctx, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen);

bool OFB_DecryptUpdate(ENCRYPT_CONTEXT* ctx, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen);

bool OFB_Final(ENCRYPT_CONTEXT* ctx, unsigned char* out, size_t* outlen);

void OFB_Free(ENCRYPT_CONTEXT* ctx);

void OFB_SetMode(ENCRYPT_MODE** mode);

#endif