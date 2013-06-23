#include <auth/hmac.h>

#include <common/ordo_errors.h>
#include <common/secure_mem.h>

#include <string.h>

/******************************************************************************/

struct HMAC_CTX
{
    const struct HASH_FUNCTION *hash;
    struct DIGEST_CTX *ctx;
    size_t digest_len;
    uint8_t *key;
};

struct HMAC_CTX* hmac_alloc(const struct HASH_FUNCTION *hash)
{
    struct HMAC_CTX *ctx = secure_alloc(sizeof(struct HMAC_CTX));
    const size_t block_size = hash_block_size(hash);

    /* We could just return nil here, but it is more consistent to just rely on
     * the hmac_free function (and it helps ensure they work well together). */
    if (!ctx) goto failure;

    if (!(ctx->ctx = digest_alloc(hash))) goto failure;
    ctx->hash = hash; /* Save the hash primitive. */

    if (!(ctx->key = secure_alloc(block_size))) goto failure;
    return ctx;

failure:
    hmac_free(ctx);
    return 0;
}

int hmac_init(struct HMAC_CTX *ctx,
              const void *key,
              size_t key_size,
              const void *hash_params)
{
    const size_t block_size = hash_block_size(ctx->hash);

    int err = ORDO_SUCCESS;
    size_t t;

    /* The key may be smaller than the hash's block size, fill with zeroes. */
    memset(ctx->key, 0x00, block_size);

    /* If the key is larger than the hash function's block size, it needs to
     * be reduced. This is done by hashing it once, as per RFC 2104. */
    if (key_size > block_size)
    {
        if ((err = digest_init(ctx->ctx, 0))) return err;
        digest_update(ctx->ctx, key, key_size);
        digest_final(ctx->ctx, ctx->key);
    }
    else memcpy(ctx->key, key, key_size);

    for (t = 0; t < block_size; ++t) ctx->key[t] ^= 0x36;
    if ((err = digest_init(ctx->ctx, hash_params))) return err;
    digest_update(ctx->ctx, ctx->key, block_size);

    return err;
}

void hmac_update(struct HMAC_CTX *ctx,
                 const void *buffer,
                 size_t size)
{
    digest_update(ctx->ctx, buffer, size);
}

int hmac_final(struct HMAC_CTX *ctx,
               void *digest)
{
    int err = ORDO_SUCCESS;

    const size_t digest_len = digest_length(ctx->hash);
    const size_t block_size = hash_block_size(ctx->hash);
    size_t t;

    /* Finalize inner hash. */
    digest_final(ctx->ctx, digest);

    /* This will implicitly go from inner mask to outer mask. */
    for (t = 0; t < block_size; ++t) ctx->key[t] ^= 0x5c ^ 0x36;

    if ((err = digest_init(ctx->ctx, 0)))
    {
        /* Now "digest" (user-provided pointer) contains sensitive data.
         * Fill it with zeroes before returning if a failure occurred. */
        secure_erase(digest, digest_len);
        return err;
    }

    digest_update(ctx->ctx, ctx->key, block_size);
    digest_update(ctx->ctx, digest, digest_len);
    digest_final(ctx->ctx, digest);

    return err;
}

/* This deallocation function is designed to be able to cope with partially
 * allocated contexts resulting from failures in hmac_alloc, such that any
 * error in the latter can be gracefully handled by calling hmac_free.
 *
 * The only condition is that if ctx->ctx has been initialized, then ctx->hash
 * must have been set to the proper hash function object. If this is not the
 * case, this function will fail. */
void hmac_free(struct HMAC_CTX *ctx)
{
    if (!ctx) return;

    if (ctx->ctx)
    {
        secure_free(ctx->key, hash_block_size(ctx->hash));
        digest_free(ctx->ctx);
    }

    secure_free(ctx, sizeof(struct HMAC_CTX));
}

void hmac_copy(struct HMAC_CTX *dst,
               const struct HMAC_CTX *src)
{
    memcpy(dst->key, src->key, hash_block_size(dst->hash));
    digest_copy(dst->ctx, src->ctx);
}
