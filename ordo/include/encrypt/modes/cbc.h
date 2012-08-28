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

/*! A parameter structure for CBC mode - this only contains whether padding should be enabled. */
typedef struct CBC_PARAMS
{
    /*! Set to 0 to disable padding, 1 to enable it. */
    size_t padding;
} CBC_PARAMS;

void CBC_Create(ENCRYPT_MODE_CONTEXT*  mode, CIPHER_PRIMITIVE_CONTEXT* cipher);

int CBC_Init(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, void* iv, CBC_PARAMS* params);

void CBC_Update(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen);

int CBC_Final(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* out, size_t* outlen);

void CBC_Free(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher);

void CBC_SetMode(ENCRYPT_MODE* mode);

#endif
