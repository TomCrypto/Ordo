#include <auth/hmac.h>

HMAC_CONTEXT* hmacCreate(HASH_FUNCTION* hash)
{
    /* Allocate the HMAC context. */
    HMAC_CONTEXT* ctx = salloc(sizeof(HMAC_CONTEXT));
    if (ctx)
    {
        /* Allocate space for the key and digest. */
        ctx->key = salloc(hash->blockSize);
        ctx->digest = salloc(hash->digestSize);
        if ((ctx->key) && (ctx->digest))
        {
            /* Allocate the hash function context. */
            ctx->ctx = hashFunctionCreate(hash);
            if (ctx->ctx) return ctx;
        }

        /* Something went wrong. */
        sfree(ctx->digest, hash->digestSize);
        sfree(ctx->key, hash->blockSize);
        sfree(ctx, sizeof(HMAC_CONTEXT));
    }

    /* Allocation failed! */
    return 0;
}

int hmacInit(HMAC_CONTEXT* ctx, void* key, size_t keySize, void* hashParams)
{
    /* Local variables. */
    int error;
    size_t t;

    /* Wipe the key block to start fresh. */
    memset(ctx->key, 0x00, ctx->ctx->hash->blockSize);

    /* First, we need to process the key. If it's smaller than the hash function's
     * block size, we just pad it with zeroes, otherwise we hash it and use that. */
    if (keySize > ctx->ctx->hash->blockSize)
    {
        /* We'll need to hash the key. */
        error = hashFunctionInit(ctx->ctx, 0);
        if (error < ORDO_ESUCCESS) return error;
        hashFunctionUpdate(ctx->ctx, key, keySize);
        hashFunctionFinal(ctx->ctx, ctx->key);
    }
    else
    {
        /* Key is small enough, just copy it there. */
        memcpy(ctx->key, key, keySize);
    }

    /* Apply the inner mask to the key block. */
    for (t = 0; t < ctx->ctx->hash->blockSize; ++t) ctx->key[t] ^= 0x36;

    /* Initialize the inner hash context. */
    error = hashFunctionInit(ctx->ctx, hashParams);
    if (error < ORDO_ESUCCESS) return error;

    /* Feed it the processed key as per RFC 2104. */
    hashFunctionUpdate(ctx->ctx, ctx->key, ctx->ctx->hash->blockSize);

    /* Success! */
    return ORDO_ESUCCESS;
}

void hmacUpdate(HMAC_CONTEXT* ctx, void* buffer, size_t size)
{
    /* Just feed in the buffer, as usual. */
    hashFunctionUpdate(ctx->ctx, buffer, size);
}

int hmacFinal(HMAC_CONTEXT* ctx, void* digest)
{
    /* Local variables. */
    int error;
    size_t t;

    /* Get the inner digest. */
    hashFunctionFinal(ctx->ctx, ctx->digest);

    /* Implicitly mask the key with the outer mask. */
    for (t = 0; t < ctx->ctx->hash->blockSize; ++t) ctx->key[t] ^= 0x5c ^ 0x36;

    /* Reinitialize the hash context for the outer hash. */
    error = hashFunctionInit(ctx->ctx, 0);
    if (error < ORDO_ESUCCESS) return error;

    /* Feed this masked key to the hash function. */
    hashFunctionUpdate(ctx->ctx, ctx->key, ctx->ctx->hash->blockSize);

    /* Feed the inner digest to the hash function. */
    hashFunctionUpdate(ctx->ctx, ctx->digest, ctx->ctx->hash->digestSize);

    /* Get the final digest - this is the HMAC. */
    hashFunctionFinal(ctx->ctx, digest);

    /* We're done! */
    return ORDO_ESUCCESS;
}

void hmacFree(HMAC_CONTEXT* ctx)
{
    /* Free in the right order. */
    sfree(ctx->digest, ctx->ctx->hash->digestSize);
    sfree(ctx->key, ctx->ctx->hash->blockSize);
    hashFunctionFree(ctx->ctx);
    sfree(ctx, sizeof(HMAC_CONTEXT));
}

void hmacCopy(HMAC_CONTEXT* dst, HMAC_CONTEXT* src)
{
    memcpy(dst->key, src->key, dst->ctx->hash->blockSize);
    memcpy(dst->digest, src->digest, dst->ctx->hash->digestSize);
    hashFunctionCopy(dst->ctx, src->ctx);
}
