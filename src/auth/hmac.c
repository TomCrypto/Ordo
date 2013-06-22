#include <auth/hmac.h>

#include <common/ordo_errors.h>
#include <common/secure_mem.h>
#include <string.h>

/******************************************************************************/

struct HMAC_CTX
{
    struct HASH_FUNCTION *hash;
    void *ctx;
    unsigned char *key;
    void *digest;
};

struct HMAC_CTX* hmac_alloc(struct HASH_FUNCTION *hash)
{
    struct HMAC_CTX *ctx = secure_alloc(sizeof(struct HMAC_CTX));
    if (!ctx) goto fail;

    if (!(ctx->ctx = hash_alloc(hash))) goto fail;

    {
        ctx->hash = hash;

        {
            size_t digest_length = hash_digest_length(ctx->hash);
            size_t block_size = hash_block_size(ctx->hash);

            if (!(ctx->key = secure_alloc(block_size))) goto fail;
            if (!(ctx->digest = secure_alloc(digest_length))) goto fail;
            return ctx;
        }
    }

fail:
    hmac_free(ctx);
    return 0;
}

int hmac_init(struct HMAC_CTX *ctx, void *key, size_t key_size, void *hash_params)
{
    size_t block_size = hash_block_size(ctx->hash);

    int err = ORDO_SUCCESS;
    size_t t;

    /* The key may be smaller than the hash's block size, fill with zeroes. */
    memset(ctx->key, 0x00, block_size);

    /* If the key is larger than the hash function's block size, it needs to
     * be reduced. This is done by hashing it once, as per RFC 2104. */
    if (key_size > block_size)
    {
        if ((err = hash_init(ctx->ctx, 0))) return err;
        hash_update(ctx->ctx, key, key_size);
        hash_final(ctx->ctx, ctx->key);
    }
    else memcpy(ctx->key, key, key_size);

    for (t = 0; t < block_size; ++t) ctx->key[t] ^= 0x36;
    if ((err = hash_init(ctx->ctx, hash_params))) return err;
    hash_update(ctx->ctx, ctx->key, block_size);

    return err;
}

void hmac_update(struct HMAC_CTX *ctx, void *buffer, size_t size)
{
    hash_update(ctx->ctx, buffer, size);
}

int hmac_final(struct HMAC_CTX *ctx, void *digest)
{
    size_t digest_length = hash_digest_length(ctx->hash);
    size_t block_size = hash_block_size(ctx->hash);

    int err = ORDO_SUCCESS;
    size_t t;

    hash_final(ctx->ctx, ctx->digest);

    for (t = 0; t < block_size; ++t) ctx->key[t] ^= 0x5c ^ 0x36;

    if ((err = hash_init(ctx->ctx, 0))) return err;
    hash_update(ctx->ctx, ctx->key, block_size);
    hash_update(ctx->ctx, ctx->digest, digest_length);
    hash_final(ctx->ctx, digest);

    return err;
}

void hmac_free(struct HMAC_CTX *ctx)
{
    if (ctx)
    {
        if (ctx->ctx)
        {
            size_t digest_length = hash_digest_length(ctx->hash);
            size_t block_size = hash_block_size(ctx->hash);

            secure_free(ctx->digest, digest_length);
            secure_free(ctx->key, block_size);
            hash_free(ctx->ctx);
        }

        secure_free(ctx, sizeof(struct HMAC_CTX));
    }
}

void hmac_copy(struct HMAC_CTX *dst, struct HMAC_CTX *src)
{
    memcpy(dst->digest, src->digest, hash_digest_length(dst->hash));
    memcpy(dst->key, src->key, hash_block_size(dst->hash));
    hash_copy(dst->ctx, src->ctx);
}
