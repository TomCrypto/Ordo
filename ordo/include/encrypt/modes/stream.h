#ifndef stream_h
#define stream_h

/**
 * @file stream.h
 * Contains the STREAM encryption mode interface (for stream ciphers only).
 *
 * Header usage mode: External.
 *
 * @see stream.c
 */

#include <encrypt/encrypt.h>

/*! This is extra context space required by the STREAM mode to store the counter and the amount of state not used.*/
typedef struct STREAM_RESERVED
{
    /*! The amount of bytes of unused state remaining before the state is to be renewed. */
    size_t remaining;
} STREAM_RESERVED;

/*! This structure describes a symmetric encryption context for the STREAM mode. */
typedef struct STREAM_ENCRYPT_CONTEXT
{
    /*! The primitive to use. */
    CIPHER_PRIMITIVE* primitive;
    /*! The mode of operation to use (this is set to the STREAM mode). */
    ENCRYPT_MODE* mode;
    /*! Points to the key material. */
    void* key;
    /*! Points to the initialization vector. */
    void* iv;
    /*! Whether to encrypt or decrypt (true = encryption). */
    int direction;
    /*! Whether padding is enabled or not. */
    int padding;
    /*! Unused space. */
    STREAM_RESERVED* reserved;
} STREAM_ENCRYPT_CONTEXT;

void STREAM_Create(STREAM_ENCRYPT_CONTEXT* ctx);

int STREAM_Init(STREAM_ENCRYPT_CONTEXT* ctx, void* key, size_t keySize, void* tweak, void* iv);

void STREAM_Update(STREAM_ENCRYPT_CONTEXT* ctx, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen);

int STREAM_Final(STREAM_ENCRYPT_CONTEXT* ctx, unsigned char* out, size_t* outlen);

void STREAM_Free(STREAM_ENCRYPT_CONTEXT* ctx);

void STREAM_SetMode(ENCRYPT_MODE* mode);

#endif
