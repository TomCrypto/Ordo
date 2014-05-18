/*===-- digest.c --------------------------------------*- generic -*- C -*-===*/

#include "ordo/digest/digest.h"

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

/*===----------------------------------------------------------------------===*/

int digest_init(struct DIGEST_CTX *ctx, enum HASH_FUNCTION hash,
                                        const void *params)
{
    return hash_function_init(&ctx->state, hash, params);
}

void digest_update(struct DIGEST_CTX *ctx,
                   const void *in, size_t in_len)
{
    hash_function_update(&ctx->state, in, in_len);
}

void digest_final(struct DIGEST_CTX *ctx, void *digest)
{
    hash_function_final(&ctx->state, digest);
}

void digest_copy(struct DIGEST_CTX *dst,
                 const struct DIGEST_CTX *src)
{
    *dst = *src;
}

size_t digest_length(enum HASH_FUNCTION hash)
{
    return hash_function_query(hash, DIGEST_LEN_Q, 0);
}
