#include <primitives/primitives.h>

/* Primitive list. */
#include <primitives/block_ciphers/nullcipher.h>
#include <primitives/block_ciphers/threefish256.h>
#include <primitives/stream_ciphers/rc4.h>

/* Primitive lists. */
BLOCK_CIPHER blockCiphers[BLOCK_CIPHER_COUNT];
STREAM_CIPHER streamCiphers[STREAM_CIPHER_COUNT];

/* Loads all primitives. */
void primitivesLoad()
{
    /* Block cipher primitives. */
    NullCipher_SetPrimitive  (&blockCiphers[BLOCK_CIPHER_NULLCIPHER]);
    Threefish256_SetPrimitive(&blockCiphers[BLOCK_CIPHER_THREEFISH256]);

    /* Stream cipher primitives. */
    RC4_SetPrimitive(&streamCiphers[STREAM_CIPHER_RC4]);

    /* Hash primitives. */
    /* empty :[ */
}

/* Pass-through functions to acquire primitives. */
BLOCK_CIPHER* NullCipher()   { return &blockCiphers[BLOCK_CIPHER_NULLCIPHER]; }
BLOCK_CIPHER* Threefish256() { return &blockCiphers[BLOCK_CIPHER_THREEFISH256]; }

STREAM_CIPHER* RC4() { return &streamCiphers[STREAM_CIPHER_RC4]; }

/* Returns a block cipher primitive object from a name. */
BLOCK_CIPHER* getBlockCipherByName(char* name)
{
    ssize_t t;
    for (t = 0; t < BLOCK_CIPHER_COUNT; t++)
    {
        /* Simply compare against the cipher list. */
        if (strcmp(name, blockCiphers[t].name) == 0) return &blockCiphers[t];
    }

    /* No match found. */
    return 0;
}

/* Returns a block cipher primitive object from an ID. */
BLOCK_CIPHER* getBlockCipherByID(size_t ID)
{
    return (ID < BLOCK_CIPHER_COUNT) ? &blockCiphers[ID] : 0;
}

/* Returns a stream cipher primitive object from a name. */
STREAM_CIPHER* getStreamCipherByName(char* name)
{
    ssize_t t;
    for (t = 0; t < STREAM_CIPHER_COUNT; t++)
    {
        /* Simply compare against the cipher list. */
        if (strcmp(name, streamCiphers[t].name) == 0) return &streamCiphers[t];
    }

    /* No match found. */
    return 0;
}

/* Returns a stream cipher primitive object from an ID. */
STREAM_CIPHER* getStreamCipherByID(size_t ID)
{
    return (ID < STREAM_CIPHER_COUNT) ? &streamCiphers[ID] : 0;
}

/* This function returns an initialized block cipher context using a specific block cipher object. */
BLOCK_CIPHER_CONTEXT* block_cipher_create(BLOCK_CIPHER* cipher)
{
    /* Allocate the cipher context. */
    return cipher->fCreate(cipher);
}

/* This function returns an initialized cipher context with the provided parameters. */
int block_cipher_init(BLOCK_CIPHER_CONTEXT* ctx, void* key, size_t keySize, void* cipherParams)
{
    /* Initialize the cipher context. */
    return ctx->cipher->fInit(ctx, key, keySize, cipherParams);
}

/* This function frees an initialized cipher context. */
void block_cipher_free(BLOCK_CIPHER_CONTEXT* ctx)
{
    /* Free the cipher context. */
    ctx->cipher->fFree(ctx);
}

/* This function returns an initialized stream cipher context using a specific block cipher object. */
STREAM_CIPHER_CONTEXT* stream_cipher_create(STREAM_CIPHER* cipher)
{
    /* Allocate the cipher context. */
    return cipher->fCreate(cipher);
}

/* This function returns an initialized cipher context with the provided parameters. */
int stream_cipher_init(STREAM_CIPHER_CONTEXT* ctx, void* key, size_t keySize, void* cipherParams)
{
    /* Initialize the cipher context. */
    return ctx->cipher->fInit(ctx, key, keySize, cipherParams);
}

/* This function frees an initialized cipher context. */
void stream_cipher_free(STREAM_CIPHER_CONTEXT* ctx)
{
    /* Free the cipher context. */
    ctx->cipher->fFree(ctx);
}
