#include <digest/digest.h>

#include <common/secure_mem.h>

/******************************************************************************/

struct DIGEST_CTX
{
    const struct HASH_FUNCTION *hash;
    void *state;
};

struct DIGEST_CTX* digest_alloc(const struct HASH_FUNCTION *hash)
{
    struct DIGEST_CTX *ctx = secure_alloc(sizeof(struct DIGEST_CTX));
    if (!ctx) goto failure;
    ctx->hash = hash;

    if (!(ctx->state = hash_function_alloc(ctx->hash))) goto failure;
    return ctx;

failure:
    digest_free(ctx);
    return 0;
}

int digest_init(struct DIGEST_CTX *ctx,
                const void *params)
{
    return hash_function_init(ctx->hash, ctx->state, params);
}

void digest_update(struct DIGEST_CTX *ctx,
                   const void *buffer,
                   size_t size)
{
    hash_function_update(ctx->hash, ctx->state, buffer, size);
}

void digest_final(struct DIGEST_CTX *ctx,
                  void *digest)
{
    hash_function_final(ctx->hash, ctx->state, digest);
}

void digest_free(struct DIGEST_CTX *ctx)
{
    hash_function_free(ctx->hash, ctx->state);
    secure_free(ctx, sizeof(struct DIGEST_CTX));
}

void digest_copy(struct DIGEST_CTX *dst,
                 const struct DIGEST_CTX *src)
{
    hash_function_copy(dst->hash, dst->state, src->state);
}

size_t digest_length(const struct HASH_FUNCTION *hash)
{
    return hash_digest_length(hash);
}
