/*===-- hmac.c ----------------------------------------*- generic -*- C -*-===*/

#include "ordo/auth/hmac.h"

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

/*===----------------------------------------------------------------------===*/

int hmac_init(struct HMAC_CTX *ctx,
              const void *key, size_t key_len,
              prim_t hash, const void *params)
{
    size_t block_size = hash_query(hash, BLOCK_SIZE_Q, 0);

    int err = ORDO_SUCCESS;
    size_t t;

    /* The key may be smaller than the hash's block size, pad with zeroes. */
    memset(ctx->key, 0x00, block_size);

    /* If the key is larger than the hash function's block size, it needs to
     * be reduced. This is done by hashing it once, as per RFC 2104. */
    if (key_len > block_size)
    {
        if ((err = digest_init(&ctx->ctx, hash, 0)))
            return err;
        digest_update(&ctx->ctx, key, key_len);
        digest_final(&ctx->ctx, ctx->key);
    }
    else memcpy(ctx->key, key, key_len);

    for (t = 0; t < block_size; ++t) ctx->key[t] ^= 0x36;
    if ((err = digest_init(&ctx->ctx, hash, params)))
        return err;

    digest_update(&ctx->ctx, ctx->key, block_size);

    return err;
}

void hmac_update(struct HMAC_CTX *ctx,
                 const void *in, size_t in_len)
{
    digest_update(&ctx->ctx, in, in_len);
}

int hmac_final(struct HMAC_CTX *ctx, void *digest)
{
    size_t digest_len = digest_length(ctx->ctx.primitive);
    size_t block_size = hash_query(ctx->ctx.primitive,
                                   BLOCK_SIZE_Q, 0);
    size_t t;
    int err;

    digest_final(&ctx->ctx, digest);

    /* This will implicitly go from inner mask to outer mask. */
    for (t = 0; t < block_size; ++t) ctx->key[t] ^= 0x5c ^ 0x36;

    if ((err = digest_init(&ctx->ctx, ctx->ctx.primitive, 0)))
        return err;

    digest_update(&ctx->ctx, ctx->key, block_size);
    digest_update(&ctx->ctx, digest, digest_len);
    digest_final(&ctx->ctx, digest);

    return ORDO_SUCCESS;
}

size_t hmac_bsize(void)
{
    return sizeof(struct HMAC_CTX);
}
