#include <primitives/primitives.h>
#include <primitives/ciphers/nullcipher.h>

#define NULLCIPHER_BLOCK (16)

CIPHER_PRIMITIVE_CONTEXT* NullCipher_Create(CIPHER_PRIMITIVE* primitive)
{
    /* Allocate no state by convention. */
    CIPHER_PRIMITIVE_CONTEXT* ctx = salloc(sizeof(CIPHER_PRIMITIVE_CONTEXT));
    if (ctx)
    {
        ctx->primitive = primitive;
        return ctx;
    }

    return 0;
}

int NullCipher_Init(CIPHER_PRIMITIVE_CONTEXT* cipher, void* key, size_t keySize, void* params)
{
    /* Ignore everything! */
    return ORDO_ESUCCESS;
}

void NullCipher_Forward(CIPHER_PRIMITIVE_CONTEXT* cipher, void* block, size_t len)
{
    /* Identity permutation... do nothing. */
}

void NullCipher_Inverse(CIPHER_PRIMITIVE_CONTEXT* cipher, void* block, size_t len)
{
    /* Idem! */
}

void NullCipher_Free(CIPHER_PRIMITIVE_CONTEXT* cipher)
{
    /* Free the 1-byte "state". */
    sfree(cipher, sizeof(CIPHER_PRIMITIVE_CONTEXT));
}

/* Fills a CIPHER_PRIMITIVE struct with the correct information. */
void NullCipher_SetPrimitive(CIPHER_PRIMITIVE* primitive)
{
    PRIMITIVE_MAKECIPHER(primitive, NULLCIPHER_BLOCK, NullCipher_Create, NullCipher_Init, NullCipher_Forward, NullCipher_Inverse, NullCipher_Free, "NullCipher");
}
