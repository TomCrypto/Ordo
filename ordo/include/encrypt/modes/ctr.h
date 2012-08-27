#ifndef ctr_h
#define ctr_h

/**
 * @file ctr.h
 * Contains the CTR encryption mode interface.
 *
 * Header usage mode: External.
 *
 * @see ctr.c
 */

#include <encrypt/encrypt.h>

void CTR_Create(ENCRYPT_MODE_CONTEXT* ctx, CIPHER_PRIMITIVE_CONTEXT* cipher);

int CTR_Init(ENCRYPT_MODE_CONTEXT* ctx, CIPHER_PRIMITIVE_CONTEXT* cipher, void* iv, void* params);

void CTR_Update(ENCRYPT_MODE_CONTEXT* ctx, CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen);

int CTR_Final(ENCRYPT_MODE_CONTEXT* ctx, CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* out, size_t* outlen);

void CTR_Free(ENCRYPT_MODE_CONTEXT* ctx, CIPHER_PRIMITIVE_CONTEXT* cipher);

void CTR_SetMode(ENCRYPT_MODE* mode);

#endif
