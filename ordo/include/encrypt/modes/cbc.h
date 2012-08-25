#ifndef cbc_h
#define cbc_h

/**
 * @file cbc.h
 * Contains the CBC encryption mode interface.
 *
 * Header usage mode: External.
 *
 * @see cbc.c
 */

#include <encrypt/encrypt.h>

void CBC_Create(ENCRYPT_CONTEXT* ctx);

int CBC_Init(ENCRYPT_CONTEXT* ctx, void* key, size_t keySize, void* tweak, void* iv, void* params);

void CBC_EncryptUpdate(ENCRYPT_CONTEXT* ctx, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen);

void CBC_DecryptUpdate(ENCRYPT_CONTEXT* ctx, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen);

int CBC_EncryptFinal(ENCRYPT_CONTEXT* ctx, unsigned char* out, size_t* outlen);

int CBC_DecryptFinal(ENCRYPT_CONTEXT* ctx, unsigned char* out, size_t* outlen);

void CBC_Free(ENCRYPT_CONTEXT* ctx);

void CBC_SetMode(ENCRYPT_MODE* mode);

#endif
