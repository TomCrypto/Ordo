#include <enc/enc_stream.h>

#include <common/secure_mem.h>

/******************************************************************************/

struct ENC_STREAM_CTX
{
    const struct STREAM_CIPHER *cipher;
    void *state;
};

struct ENC_STREAM_CTX* enc_stream_alloc(const struct STREAM_CIPHER *cipher)
{
    struct ENC_STREAM_CTX *ctx = secure_alloc(sizeof(struct ENC_STREAM_CTX));
    if (!ctx) goto fail;
    ctx->cipher = cipher;

    if (!(ctx->state = stream_cipher_alloc(ctx->cipher))) goto fail;
    return ctx;

fail:
    enc_stream_free(ctx);
    return 0;
}

int enc_stream_init(struct ENC_STREAM_CTX *ctx,
                    const void *key,
                    size_t key_size,
                    const void *params)
{
    return stream_cipher_init(ctx->cipher, ctx->state, key, key_size, params);
}

void enc_stream_update(struct ENC_STREAM_CTX *ctx,
                       void *buffer,
                       size_t len)
{
    stream_cipher_update(ctx->cipher, ctx->state, buffer, len);
}

void enc_stream_free(struct ENC_STREAM_CTX *ctx)
{
    stream_cipher_free(ctx->cipher, ctx->state);
    secure_free(ctx, sizeof(struct ENC_STREAM_CTX));
}

void enc_stream_copy(struct ENC_STREAM_CTX *dst,
                     const struct ENC_STREAM_CTX *src)
{
    stream_cipher_copy(dst->cipher, dst->state, src->state);
}

size_t enc_stream_key_len(const struct STREAM_CIPHER *cipher,
                          size_t key_len)
{
    return stream_cipher_key_len(cipher, key_len);
}
