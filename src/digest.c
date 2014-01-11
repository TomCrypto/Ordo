//===-- digest.c --------------------------------------*- generic -*- C -*-===//

#include "ordo/digest/digest.h"

/// @cond
#include "ordo/internal/implementation.h"
/// @endcond

//===----------------------------------------------------------------------===//

struct DIGEST_CTX
{
    const struct HASH_FUNCTION *hash;
    void *state;
};

struct DIGEST_CTX *digest_alloc(const struct HASH_FUNCTION *hash)
{
    struct DIGEST_CTX *ctx = mem_alloc(sizeof(*ctx));
    if (!ctx) goto fail;
    ctx->hash = hash;

    ctx->state = hash_function_alloc(ctx->hash);
    if (!ctx->state) goto fail;

    return ctx;

fail:
    digest_free(ctx);
    return 0;
}

int digest_init(struct DIGEST_CTX *ctx, const void *params)
{
    return hash_function_init(ctx->hash, ctx->state, params);
}

void digest_update(struct DIGEST_CTX *ctx,
                   const void *in, size_t in_len)
{
    hash_function_update(ctx->hash, ctx->state, in, in_len);
}

void digest_final(struct DIGEST_CTX *ctx, void *digest)
{
    hash_function_final(ctx->hash, ctx->state, digest);
}

void digest_free(struct DIGEST_CTX *ctx)
{
    if (ctx) hash_function_free(ctx->hash, ctx->state);

    mem_free(ctx);
}

void digest_copy(struct DIGEST_CTX *dst,
                 const struct DIGEST_CTX *src)
{
    hash_function_copy(dst->hash, dst->state, src->state);
}

size_t digest_length(const struct HASH_FUNCTION *hash)
{
    return hash_function_query(hash, DIGEST_LEN_Q, 0);
}
