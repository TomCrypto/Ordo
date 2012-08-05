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

#include "encrypt.h"

/*! This is extra context space required by the CTR mode to store the counter and the amount of state not used.*/
typedef struct CTR_RESERVED
{
    /*! The counter value. */
    unsigned char* counter;
    /*! The amount of bytes of unused state remaining before the state is to be renewed. */
    size_t remaining;
} CTR_RESERVED;

/*! This structure describes a symmetric encryption context for the CTR mode. */
typedef struct CTR_ENCRYPT_CONTEXT
{
    /*! The primitive to use. */
    CIPHER_PRIMITIVE* primitive;
    /*! The mode of operation to use (this is set to the CTR mode). */
    ENCRYPT_MODE* mode;
    /*! Points to the key material. */
    void* key;
    /*! Points to the initialization vector. */
    void* iv;
    /*! Whether to encrypt or decrypt (true = encryption). */
    int direction;
    /*! Whether padding is enabled or not. */
    int padding;
    /*! Reserved space for the CTR mode of operation. */
    CTR_RESERVED* reserved;
} CTR_ENCRYPT_CONTEXT;

void CTR_Create(CTR_ENCRYPT_CONTEXT* ctx);

int CTR_Init(CTR_ENCRYPT_CONTEXT* ctx, void* key, size_t keySize, void* tweak, void* iv);

void CTR_Update(CTR_ENCRYPT_CONTEXT* ctx, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen);

int CTR_Final(CTR_ENCRYPT_CONTEXT* ctx, unsigned char* out, size_t* outlen);

void CTR_Free(CTR_ENCRYPT_CONTEXT* ctx);

void CTR_SetMode(ENCRYPT_MODE* mode);

#endif
