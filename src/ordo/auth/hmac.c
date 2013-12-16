#include "ordo/auth/hmac.h"

#include "ordo/internal/mem.h"
#include "ordo/common/utils.h"

#include <string.h>

/******************************************************************************/

struct HMAC_CTX
{
    const struct HASH_FUNCTION *hash;
    struct DIGEST_CTX *ctx;
    unsigned char *key;
    size_t digest_len;
};

struct HMAC_CTX * ORDO_CALLCONV
hmac_alloc(const struct HASH_FUNCTION *hash)
{
    struct HMAC_CTX *ctx = mem_alloc(sizeof(struct HMAC_CTX));
    size_t block_size = hash_function_query(hash, BLOCK_SIZE, 0);

    /* We could just return nil here, but it is more consistent to rely on
     * the hmac_free function (and helps ensure they work well together). */
    if (!ctx) goto fail;

    if (!(ctx->ctx = digest_alloc(hash))) goto fail;
    ctx->hash = hash; /* Save the hash primitive. */

    if (!(ctx->key = mem_alloc(block_size))) goto fail;
    return ctx;

fail:
    hmac_free(ctx);
    return 0;
}

int ORDO_CALLCONV
hmac_init(struct HMAC_CTX *ctx,
          const void *key, size_t key_len,
          const void *hash_params)
{
    size_t block_size = hash_function_query(ctx->hash, BLOCK_SIZE, 0);

    int err = ORDO_SUCCESS;
    size_t t;

    /* The key may be smaller than the hash's block size, fill with zeroes. */
    memset(ctx->key, 0x00, block_size);

    /* If the key is larger than the hash function's block size, it needs to
     * be reduced. This is done by hashing it once, as per RFC 2104. */
    if (key_len > block_size)
    {
        if ((err = digest_init(ctx->ctx, 0))) return err;
        digest_update(ctx->ctx, key, key_len);
        digest_final(ctx->ctx, ctx->key);
    }
    else memcpy(ctx->key, key, key_len);

    for (t = 0; t < block_size; ++t) ctx->key[t] ^= 0x36;
    if ((err = digest_init(ctx->ctx, hash_params))) return err;
    digest_update(ctx->ctx, ctx->key, block_size);

    return err;
}

void ORDO_CALLCONV
hmac_update(struct HMAC_CTX *ctx,
            const void *in, size_t in_len)
{
    digest_update(ctx->ctx, in, in_len);
}

int ORDO_CALLCONV
hmac_final(struct HMAC_CTX *ctx, void *digest)
{
    int err = ORDO_SUCCESS;

    size_t digest_len = digest_length(ctx->hash);
    size_t block_size = hash_function_query(ctx->hash, BLOCK_SIZE, 0);
    size_t t;

    /* Finalize inner hash. */
    digest_final(ctx->ctx, digest);

    /* This will implicitly go from inner mask to outer mask. */
    for (t = 0; t < block_size; ++t) ctx->key[t] ^= 0x5c ^ 0x36;

    if ((err = digest_init(ctx->ctx, 0)))
    {
        /* Now "digest" (user-provided pointer) contains sensitive data.
         * Fill it with zeroes before returning if a failure occurred. */
        mem_erase(digest, digest_len);
        return err;
    }

    digest_update(ctx->ctx, ctx->key, block_size);
    digest_update(ctx->ctx, digest, digest_len);
    digest_final(ctx->ctx, digest);

    return err;
}

void ORDO_CALLCONV
hmac_free(struct HMAC_CTX *ctx)
{
    if (!ctx) return;

    if (ctx->ctx)
    {
        mem_free(ctx->key);
        digest_free(ctx->ctx);
    }

    mem_free(ctx);
}

void ORDO_CALLCONV hmac_copy(struct HMAC_CTX *dst, const struct HMAC_CTX *src)
{
    size_t block_size = hash_function_query(dst->hash, BLOCK_SIZE, 0);
    memcpy(dst->key, src->key, block_size);
    digest_copy(dst->ctx, src->ctx);
}
