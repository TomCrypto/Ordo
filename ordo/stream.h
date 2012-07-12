/**
 * @file STREAM.h
 * Contains the STREAM encryption mode interface (for stream ciphers only).
 * 
 * Header usage mode: External.
 *
 * @see STREAM.c
 */

#ifndef stream_h
#define stream_h

#include "encrypt.h"

void STREAM_Create(ENCRYPT_CONTEXT* ctx);

bool STREAM_Init(ENCRYPT_CONTEXT* ctx, void* key, size_t keySize, void* tweak, void* iv);

bool STREAM_EncryptUpdate(ENCRYPT_CONTEXT* ctx, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen);

bool STREAM_DecryptUpdate(ENCRYPT_CONTEXT* ctx, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen);

bool STREAM_Final(ENCRYPT_CONTEXT* ctx, unsigned char* out, size_t* outlen);

void STREAM_Free(ENCRYPT_CONTEXT* ctx);

void STREAM_SetMode(ENCRYPT_MODE** mode);

#endif