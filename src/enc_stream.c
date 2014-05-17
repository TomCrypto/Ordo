/*===-- enc_stream.c ----------------------------------*- generic -*- C -*-===*/

#include "ordo/enc/enc_stream.h"

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

/*===----------------------------------------------------------------------===*/

int enc_stream_init(struct ENC_STREAM_CTX *ctx,
                    const void *key,
                    size_t key_size,
                    const struct STREAM_CIPHER *cipher,
                    const void *params)
{
    return stream_cipher_init(ctx->cipher = cipher, ctx->state, key, key_size, params);
}

void enc_stream_update(struct ENC_STREAM_CTX *ctx,
                       void *buffer,
                       size_t len)
{
    stream_cipher_update(ctx->cipher, ctx->state, buffer, len);
}

void enc_stream_final(struct ENC_STREAM_CTX *ctx)
{
    stream_cipher_final(ctx->cipher, ctx->state);
}

void enc_stream_copy(struct ENC_STREAM_CTX *dst,
                     const struct ENC_STREAM_CTX *src)
{
    *dst = *src;
}

size_t enc_stream_key_len(const struct STREAM_CIPHER *cipher,
                          size_t key_len)
{
    return stream_cipher_query(cipher, KEY_LEN_Q, key_len);
}
