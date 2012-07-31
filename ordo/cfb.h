/**
 * @file cfb.h
 * Contains the CFB encryption mode interface.
 *
 * Header usage mode: External.
 *
 * @see cfb.c
 */

#ifndef cfb_h
#define cfb_h

#include "encrypt.h"

void CFB_Create(ENCRYPT_CONTEXT* ctx);

int CFB_Init(ENCRYPT_CONTEXT* ctx, void* key, size_t keySize, void* tweak, void* iv);

void CFB_EncryptUpdate(ENCRYPT_CONTEXT* ctx, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen);

void CFB_DecryptUpdate(ENCRYPT_CONTEXT* ctx, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen);

int CFB_Final(ENCRYPT_CONTEXT* ctx, unsigned char* out, size_t* outlen);

void CFB_Free(ENCRYPT_CONTEXT* ctx);

void CFB_SetMode(ENCRYPT_MODE** mode);

#endif
