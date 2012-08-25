#ifndef ecb_h
#define ecb_h

/**
 * @file ecb.h
 * Contains the ECB encryption mode interface.
 *
 * Header usage mode: External.
 *
 * @see ecb.c
 */

#include <encrypt/encrypt.h>

void ECB_Create(ENCRYPT_CONTEXT* ctx);

int ECB_Init(ENCRYPT_CONTEXT* ctx, void* key, size_t keySize, void* tweak, void* iv, void* params);

void ECB_EncryptUpdate(ENCRYPT_CONTEXT* ctx, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen);

void ECB_DecryptUpdate(ENCRYPT_CONTEXT* ctx, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen);

int ECB_EncryptFinal(ENCRYPT_CONTEXT* ctx, unsigned char* out, size_t* outlen);

int ECB_DecryptFinal(ENCRYPT_CONTEXT* ctx, unsigned char* out, size_t* outlen);

void ECB_Free(ENCRYPT_CONTEXT* ctx);

void ECB_SetMode(ENCRYPT_MODE* mode);

#endif
