#include <hash/hash.h>

#include <common/secure_mem.h>

/******************************************************************************/

/*! \brief hash function context.
 *
 * This structure describes a hash function primitive context. It is used by
 * hash functions to maintain their state across function calls (such as
 * current message block and total length, extra metadata, etc...). */
struct HASH_CTX
{
    /*! The hash function in use. */
    struct HASH_FUNCTION* hash;
    /*! The low-level hash function context. */
    void* ctx;
};

struct HASH_CTX* hash_alloc(struct HASH_FUNCTION* hash)
{
    struct HASH_CTX* ctx = secure_alloc(sizeof(struct HASH_CTX));
    if (ctx)
    {
        ctx->hash = hash;
        ctx->ctx = hash_function_alloc(ctx->hash);
        if (!ctx->ctx)
        {
            secure_free(ctx, sizeof(struct HASH_CTX));
            return 0;
        }

        return ctx;
    }

    return 0;
}

int hash_init(struct HASH_CTX* ctx,
              void* hashParams)
{
    return hash_function_init(ctx->hash, ctx->ctx, hashParams);
}

void hash_update(struct HASH_CTX* ctx,
                 void* buffer, size_t size)
{
    hash_function_update(ctx->hash, ctx->ctx, buffer, size);
}

void hash_final(struct HASH_CTX* ctx,
                void* digest)
{
    hash_function_final(ctx->hash, ctx->ctx, digest);
}

void hash_free(struct HASH_CTX* ctx)
{
    hash_function_free(ctx->hash, ctx->ctx);
    secure_free(ctx, sizeof(struct HASH_CTX));
}

void hash_copy(struct HASH_CTX* dst, struct HASH_CTX* src)
{
    hash_function_copy(dst->hash, dst->ctx, src->ctx);
}
