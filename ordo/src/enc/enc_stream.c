#include <enc/enc_stream.h>

ENC_STREAM_CIPHER_CONTEXT* encStreamCipherCreate(STREAM_CIPHER* cipher)
{
    /* Allocate the encryption context. */
    ENC_STREAM_CIPHER_CONTEXT* ctx = salloc(sizeof(ENC_STREAM_CIPHER_CONTEXT));
    if (ctx)
    {
        /* Create the cipher context. */
        if ((ctx->cipherCtx = streamCipherCreate(cipher))) return ctx;
        sfree(ctx, sizeof(ENC_STREAM_CIPHER_CONTEXT));
    };

    /* Fail, return zero. */
    return 0;
}

int encStreamCipherInit(ENC_STREAM_CIPHER_CONTEXT* ctx, void* key, size_t keySize, void* cipherParams)
{
    /* Initialize the cipher context. */
    return streamCipherInit(ctx->cipherCtx, key, keySize, cipherParams);
}

void encStreamCipherUpdate(ENC_STREAM_CIPHER_CONTEXT* ctx, unsigned char* inout, size_t len)
{
    /* Encrypt the given buffer. */
    ctx->cipherCtx->cipher->fUpdate(ctx->cipherCtx, inout, len);
}

void encStreamCipherFree(ENC_STREAM_CIPHER_CONTEXT* ctx)
{
    /* Free the encryption mode context. */
    streamCipherFree(ctx->cipherCtx);

    /* Free the context. */
    sfree(ctx, sizeof(ENC_STREAM_CIPHER_CONTEXT));
}
