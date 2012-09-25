#include <primitives/primitives.h>
#include <primitives/block_ciphers/nullcipher.h>

#define NULLCIPHER_BLOCK (16)

BLOCK_CIPHER_CONTEXT* NullCipher_Create()
{
    /* Allocate no state here. */
    BLOCK_CIPHER_CONTEXT* ctx = salloc(sizeof(BLOCK_CIPHER_CONTEXT));
    return ctx;
}

int NullCipher_Init(BLOCK_CIPHER_CONTEXT* ctx, void* key, size_t keySize, void* params)
{
    /* Ignore everything! */
    return ORDO_ESUCCESS;
}

void NullCipher_Forward(BLOCK_CIPHER_CONTEXT* ctx, void* block)
{
    /* Identity permutation... do nothing. */
}

void NullCipher_Inverse(BLOCK_CIPHER_CONTEXT* ctx, void* block)
{
    /* Idem! */
}

void NullCipher_Free(BLOCK_CIPHER_CONTEXT* ctx)
{
    /* Free the 1-byte "state". */
    sfree(ctx, sizeof(BLOCK_CIPHER_CONTEXT));
}

/* Fills a BLOCK_CIPHER struct with the correct information. */
void NullCipher_SetPrimitive(BLOCK_CIPHER* cipher)
{
    MAKE_BLOCK_CIPHER(cipher, NULLCIPHER_BLOCK, NullCipher_Create, NullCipher_Init, NullCipher_Forward, NullCipher_Inverse, NullCipher_Free, "NullCipher");
}
