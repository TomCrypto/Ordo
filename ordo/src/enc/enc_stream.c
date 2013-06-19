#include <enc/enc_stream.h>

#include <common/secure_mem.h>

/******************************************************************************/

/*! \brief Stream cipher context.
 *
 * This structure describes a stream cipher primitive context. It is used by
 * stream ciphers to maintain their state across function calls (usually,
 * stream ciphers store their internal state in it). */
struct ENC_STREAM_CTX
{
    /*! The stream cipher in use. */
    struct STREAM_CIPHER* cipher;
    /*! The low-level stream cipher context. */
    void* ctx;
};

struct ENC_STREAM_CTX* enc_stream_alloc(struct STREAM_CIPHER* cipher)
{
    struct ENC_STREAM_CTX* ctx = secure_alloc(sizeof(struct ENC_STREAM_CTX));
    if (ctx)
    {
        ctx->cipher = cipher;
        ctx->ctx = stream_cipher_alloc(ctx->cipher);
        if (!ctx->ctx)
        {
            secure_free(ctx, sizeof(struct ENC_STREAM_CTX));
            return 0;
        }

        return ctx;
    }

    return 0;
}

int enc_stream_init(struct ENC_STREAM_CTX* ctx, void* key, size_t keySize, void* cipherParams)
{
    return stream_cipher_init(ctx->cipher, ctx->ctx, key, keySize, cipherParams);
}

void enc_stream_update(struct ENC_STREAM_CTX* ctx, void* inout, size_t len)
{
    stream_cipher_update(ctx->cipher, ctx->ctx, inout, len);
}

void enc_stream_free(struct ENC_STREAM_CTX* ctx)
{
    stream_cipher_free(ctx->cipher, ctx->ctx);
    secure_free(ctx, sizeof(struct ENC_STREAM_CTX));
}
