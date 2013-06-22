#include <digest/digest.h>

#include <common/secure_mem.h>

/******************************************************************************/

struct DIGEST_CTX
{
    struct HASH_FUNCTION* hash;
    void* ctx;
};

struct DIGEST_CTX* digest_alloc(struct HASH_FUNCTION* hash)
{
    struct DIGEST_CTX* ctx = secure_alloc(sizeof(struct DIGEST_CTX));
    if (ctx)
    {
        ctx->hash = hash;
        ctx->ctx = hash_function_alloc(ctx->hash);
        if (!ctx->ctx)
        {
            secure_free(ctx, sizeof(struct DIGEST_CTX));
            return 0;
        }

        return ctx;
    }

    return 0;
}

int digest_init(struct DIGEST_CTX* ctx,
                void* hashParams)
{
    return hash_function_init(ctx->hash, ctx->ctx, hashParams);
}

void digest_update(struct DIGEST_CTX* ctx,
                   void* buffer, size_t size)
{
    hash_function_update(ctx->hash, ctx->ctx, buffer, size);
}

void digest_final(struct DIGEST_CTX* ctx,
                  void* digest)
{
    hash_function_final(ctx->hash, ctx->ctx, digest);
}

void digest_free(struct DIGEST_CTX* ctx)
{
    hash_function_free(ctx->hash, ctx->ctx);
    secure_free(ctx, sizeof(struct DIGEST_CTX));
}

void digest_copy(struct DIGEST_CTX* dst, struct DIGEST_CTX* src)
{
    hash_function_copy(dst->hash, dst->ctx, src->ctx);
}
