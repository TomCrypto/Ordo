#include <primitives/primitives.h>

/* Primitive list. */
#include <primitives/ciphers/nullcipher.h>
#include <primitives/ciphers/threefish256.h>
#include <primitives/ciphers/rc4.h>

/* Cipher primitive list. */
CIPHER_PRIMITIVE ciphers[CIPHER_COUNT];

/* Loads all primitives. */
void primitivesLoad()
{
    /* Cipher primitives. */
    NullCipher_SetPrimitive  (&ciphers[CIPHER_NULLCIPHER]);
    Threefish256_SetPrimitive(&ciphers[CIPHER_THREEFISH256]);
    RC4_SetPrimitive         (&ciphers[CIPHER_RC4]);

    /* Hash primitives. */
    /* empty :[ */
}

/* Pass-through functions to acquire primitives. */
CIPHER_PRIMITIVE* NullCipher()   { return &ciphers[CIPHER_NULLCIPHER]; }
CIPHER_PRIMITIVE* Threefish256() { return &ciphers[CIPHER_THREEFISH256]; }
CIPHER_PRIMITIVE* RC4()          { return &ciphers[CIPHER_RC4]; }

/* Returns a cipher primitive object from a name. */
CIPHER_PRIMITIVE* getCipherPrimitiveByName(char* name)
{
    ssize_t t;
    for (t = 0; t < CIPHER_COUNT; t++)
    {
        /* Simply compare against the cipher list. */
        if (strcmp(name, ciphers[t].name) == 0) return &ciphers[t];
    }

    /* No match found. */
    return 0;
}

/* Returns a cipher primitive object from an ID. */
CIPHER_PRIMITIVE* getCipherPrimitiveByID(size_t ID)
{
    return (ID < CIPHER_COUNT) ? &ciphers[ID] : 0;
}

/* This function returns an initialized cipher primitive context using a specific primitive object. */
CIPHER_PRIMITIVE_CONTEXT* cipherCreate(CIPHER_PRIMITIVE* primitive)
{
    /* Allocate the cipher context. */
    return primitive->fCreate(primitive);
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
}
