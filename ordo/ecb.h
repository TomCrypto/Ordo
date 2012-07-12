/**
 * @file ECB.h
 * Contains the ECB encryption mode interface.
 * 
 * Header usage mode: External.
 *
 * @see ECB.c
 */

#ifndef ecb_h
#define ecb_h

#include "encrypt.h"

void ECB_Create(ENCRYPT_CONTEXT* ctx);

bool ECB_Init(ENCRYPT_CONTEXT* ctx, void* key, size_t keySize, void* tweak, void* iv);

bool ECB_EncryptUpdate(ENCRYPT_CONTEXT* ctx, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen);

bool ECB_DecryptUpdate(ENCRYPT_CONTEXT* ctx, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen);

bool ECB_EncryptFinal(ENCRYPT_CONTEXT* ctx, unsigned char* out, size_t* outlen);

bool ECB_DecryptFinal(ENCRYPT_CONTEXT* ctx, unsigned char* out, size_t* outlen);

void ECB_Free(ENCRYPT_CONTEXT* ctx);

void ECB_SetMode(ENCRYPT_MODE** mode);

#endif