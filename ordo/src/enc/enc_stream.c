#include <enc/enc_stream.h>

ENC_STREAM_CONTEXT* enc_stream_create(STREAM_CIPHER* cipher)
{
    /* Allocate the encryption context. */
    ENC_STREAM_CONTEXT* ctx = salloc(sizeof(ENC_STREAM_CONTEXT));
    if (ctx)
    {
        /* Create the cipher context. */
        if ((ctx->cipherCtx = stream_cipher_create(cipher))) return ctx;
        sfree(ctx, sizeof(ENC_STREAM_CONTEXT));
    };

    /* Fail, return zero. */
    return 0;
}

int enc_stream_init(ENC_STREAM_CONTEXT* ctx, void* key, size_t keySize, void* cipherParams)
{
    /* Initialize the cipher context. */
    return stream_cipher_init(ctx->cipherCtx, key, keySize, cipherParams);
}

void enc_stream_update(ENC_STREAM_CONTEXT* ctx, unsigned char* inout, size_t len)
{
    /* Encrypt the given buffer. */
    ctx->cipherCtx->cipher->fUpdate(ctx->cipherCtx, inout, len);
}

void enc_stream_free(ENC_STREAM_CONTEXT* ctx)
{
    /* Free the encryption mode context. */
    stream_cipher_free(ctx->cipherCtx);

    /* Free the context. */
    sfree(ctx, sizeof(ENC_STREAM_CONTEXT));
}
