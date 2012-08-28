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

/*! A parameter structure for ECB mode - this only contains whether padding should be enabled. */
typedef struct ECB_PARAMS
{
    /*! Set to 0 to disable padding, 1 to enable it. */
    size_t padding;
} ECB_PARAMS;

void ECB_Create(ENCRYPT_MODE_CONTEXT*  mode, CIPHER_PRIMITIVE_CONTEXT* cipher);

int ECB_Init(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, void* iv, ECB_PARAMS* params);

void ECB_Update(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen);

int ECB_Final(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* out, size_t* outlen);

void ECB_Free(ENCRYPT_MODE_CONTEXT* mode, CIPHER_PRIMITIVE_CONTEXT* cipher);

void ECB_SetMode(ENCRYPT_MODE* mode);

#endif
