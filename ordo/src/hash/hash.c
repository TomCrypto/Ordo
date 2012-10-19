#include <hash/hash.h>

/* This function returns an initialized hash function context using a specific hash function object. */
HASH_FUNCTION_CONTEXT* hashFunctionCreate(HASH_FUNCTION* hash)
{
    /* Allocate the context. */
    HASH_FUNCTION_CONTEXT* ctx = hash->fCreate();
    if (ctx) ctx->hash = hash;
    return ctx;
}

/* This function returns an initialized hash function context with the provided parameters. */
int hashFunctionInit(HASH_FUNCTION_CONTEXT* ctx, void* hashParams)
{
    /* Initialize the context. */
    return ctx->hash->fInit(ctx, hashParams);
}

/* This function updates a hash function context, feeding more data in it. */
void hashFunctionUpdate(HASH_FUNCTION_CONTEXT* ctx, void* buffer, size_t size)
{
    /* Update the hash function context. */
    ctx->hash->fUpdate(ctx, buffer, size);
}

/* This function finalizes a hash function context, returning the final digest. */
void hashFunctionFinal(HASH_FUNCTION_CONTEXT* ctx, void* digest)
{
    /* Finalize the hash function context. */
    ctx->hash->fFinal(ctx, digest);
}

/* This function frees an initialized hash function context. */
void hashFunctionFree(HASH_FUNCTION_CONTEXT* ctx)
{
    /* Free the context. */
    ctx->hash->fFree(ctx);
}
