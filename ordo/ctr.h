/**
 * @file CTR.h
 * Contains the CTR encryption mode interface.
 *
 * Header usage mode: External.
 *
 * @see CTR.c
 */

#ifndef ctr_h
#define ctr_h

#include "encrypt.h"

void CTR_Create(ENCRYPT_CONTEXT* ctx);

int CTR_Init(ENCRYPT_CONTEXT* ctx, void* key, size_t keySize, void* tweak, void* iv);

void CTR_Update(ENCRYPT_CONTEXT* ctx, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen);

int CTR_Final(ENCRYPT_CONTEXT* ctx, unsigned char* out, size_t* outlen);

void CTR_Free(ENCRYPT_CONTEXT* ctx);

void CTR_SetMode(ENCRYPT_MODE** mode);

#endif
