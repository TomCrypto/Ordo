#ifndef cfb_h
#define cfb_h

/**
 * @file cfb.h
 * Contains the CFB encryption mode interface.
 *
 * Header usage mode: External.
 *
 * @see cfb.c
 */

#include <encrypt/encrypt.h>

/*! This is extra context space required by the CFB mode to store the amount of state not used.*/
typedef struct CFB_RESERVED
{
    /*! The amount of bytes of unused state remaining before the state is to be renewed. */
    size_t remaining;
} CFB_RESERVED;

/*! This structure describes a symmetric encryption context for the OFB mode. */
typedef struct CFB_ENCRYPT_CONTEXT
{
    /*! The primitive to use. */
    CIPHER_PRIMITIVE* primitive;
    /*! The mode of operation to use (this is set to the OFB mode). */
    ENCRYPT_MODE* mode;
    /*! Points to the key material. */
    void* key;
    /*! Points to the initialization vector. */
    void* iv;
    /*! Whether to encrypt or decrypt (true = encryption). */
    int direction;
    /*! Whether padding is enabled or not. */
    int padding;
    /*! Reserved space for the OFB mode of operation. */
    CFB_RESERVED* reserved;
} CFB_ENCRYPT_CONTEXT;

void CFB_Create(CFB_ENCRYPT_CONTEXT* ctx);

int CFB_Init(CFB_ENCRYPT_CONTEXT* ctx, void* key, size_t keySize, void* tweak, void* iv, void* params);

void CFB_EncryptUpdate(CFB_ENCRYPT_CONTEXT* ctx, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen);

void CFB_DecryptUpdate(CFB_ENCRYPT_CONTEXT* ctx, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen);

int CFB_Final(CFB_ENCRYPT_CONTEXT* ctx, unsigned char* out, size_t* outlen);

void CFB_Free(CFB_ENCRYPT_CONTEXT* ctx);

void CFB_SetMode(ENCRYPT_MODE* mode);

#endif
