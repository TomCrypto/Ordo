#include <primitives/primitives.h>

/* Primitive list. */
#include <primitives/ciphers/nullcipher.h>
#include <primitives/ciphers/threefish256.h>
#include <primitives/ciphers/rc4.h>

/* Cipher primitive list. */
CIPHER_PRIMITIVE* _NullCipher;
CIPHER_PRIMITIVE* _RC4;
CIPHER_PRIMITIVE* _Threefish256;

/* Loads all primitives. */
void loadPrimitives()
{
    /* Cipher primitives. */
    _NullCipher = malloc(sizeof(CIPHER_PRIMITIVE));
    NullCipher_SetPrimitive(_NullCipher);

    _Threefish256 = malloc(sizeof(CIPHER_PRIMITIVE));
    Threefish256_SetPrimitive(_Threefish256);

    _RC4 = malloc(sizeof(CIPHER_PRIMITIVE));
    RC4_SetPrimitive(_RC4);

    /* Hash primitives. */
    /* empty :[ */
}

/* Unloads all primitives. */
void unloadPrimitives()
{
    free(_NullCipher);
    free(_Threefish256);
    free(_RC4);
}

/* Pass-through functions to acquire primitives. */
CIPHER_PRIMITIVE* NullCipher() { return _NullCipher; }
CIPHER_PRIMITIVE* RC4() { return _RC4; }
CIPHER_PRIMITIVE* Threefish256() { return _Threefish256; }

/* This function returns an initialized cipher primitive context using a specific primitive. */
CIPHER_PRIMITIVE_CONTEXT* cipherCreate(CIPHER_PRIMITIVE* primitive)
{
    /* Allocate the cipher context. */
    CIPHER_PRIMITIVE_CONTEXT* ctx = salloc(sizeof(CIPHER_PRIMITIVE_CONTEXT));
    if (ctx)
    {
        /* If the allocation succeeded, create the context. */
        ctx->primitive = primitive;
        primitive->fCreate(ctx);
    }

    /* Return the context (allocated or not). */
    return ctx;
}

/* This function returns an initialized cipher context with the provided parameters. */
int cipherInit(CIPHER_PRIMITIVE_CONTEXT* ctx, void* key, size_t keySize, void* cipherParams)
{
    /* Initialize the cipher context. */
    return ctx->primitive->fInit(ctx, key, keySize, cipherParams);
}

/* This function frees an initialized cipher context. */
void cipherFree(CIPHER_PRIMITIVE_CONTEXT* ctx)
{
    /* Free the cipher context. */
    ctx->primitive->fFree(ctx);
    sfree(ctx, sizeof(CIPHER_PRIMITIVE_CONTEXT));
}
