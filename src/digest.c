/*===-- digest.c --------------------------------------*- generic -*- C -*-===*/

#include "ordo/digest/digest.h"

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

/*===----------------------------------------------------------------------===*/

int digest_init(struct DIGEST_CTX *ctx, const struct HASH_FUNCTION *hash,
                                        const void *params)
{
    return hash_function_init(ctx->hash = hash, ctx->state, params);
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

void digest_copy(struct DIGEST_CTX *dst,
                 const struct DIGEST_CTX *src)
{
    *dst = *src;
}

size_t digest_length(const struct HASH_FUNCTION *hash)
{
    return hash_function_query(hash, DIGEST_LEN_Q, 0);
}
