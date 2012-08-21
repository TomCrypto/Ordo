/**
 * @file encrypt.c
 * Implements the Ordo encryption interface.
 *
 * TBD!
 *
 * \todo Optimize streaming modes by using bigger word sizes than bytes if the buffer is large enough.
 *
 * @see encrypt.h
 */

/* Handles code related to symmetric ciphers (e.g. modes of operation). */
#include <primitives/primitives.h>
#include <encrypt/encrypt.h>

/* Mode of operation list. */
#include <encrypt/modes/ecb.h>
#include <encrypt/modes/cbc.h>
#include <encrypt/modes/ctr.h>
#include <encrypt/modes/ofb.h>
#include <encrypt/modes/cfb.h>
#include <encrypt/modes/stream.h>

/* Loads all cipher modes. */
void loadEncryptModes()
{
    ECB = malloc(sizeof(ENCRYPT_MODE));
    ECB_SetMode(ECB);
    CBC = malloc(sizeof(ENCRYPT_MODE));
    CBC_SetMode(CBC);
    CTR = malloc(sizeof(ENCRYPT_MODE));
    CTR_SetMode(CTR);
    OFB = malloc(sizeof(ENCRYPT_MODE));
    OFB_SetMode(OFB);
    CFB = malloc(sizeof(ENCRYPT_MODE));
    CFB_SetMode(CFB);
    STREAM = malloc(sizeof(ENCRYPT_MODE));
    STREAM_SetMode(STREAM);
}

/* Unloads all cipher modes. */
void unloadEncryptModes()
{
    free(ECB);
    free(CBC);
    free(CTR);
    free(OFB);
    free(CFB);
    free(STREAM);
}

/* This function returns an initialized encryption context using a specific primitive and mode of operation. */
ENCRYPT_CONTEXT* encryptCreate(CIPHER_PRIMITIVE* primitive, ENCRYPT_MODE* mode, int direction, int padding)
{
    ENCRYPT_CONTEXT* ctx = salloc(sizeof(ENCRYPT_CONTEXT));
    ctx->direction = direction;
    ctx->primitive = primitive;
    ctx->padding = padding;
    mode->fCreate(ctx);
    ctx->mode = mode;
    return ctx;
}

/* This function returns an initialized cipher context with the provided parameters. */
int encryptInit(ENCRYPT_CONTEXT* ctx, void* key, size_t keySize, void* tweak, void* iv, void* params)
{
    /* Initialize the cipher context. */
    return ctx->mode->fInit(ctx, key, keySize, tweak, iv, params);
}

/* This function encrypts data using the passed cipher context. If decrypt is true, the cipher will decrypt instead. */
void encryptUpdate(ENCRYPT_CONTEXT* ctx, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
{
    /* Encrypt or decrypt the buffer. */
    if (ctx->direction) ctx->mode->fEncryptUpdate(ctx, in, inlen, out, outlen);
    else ctx->mode->fDecryptUpdate(ctx, in, inlen, out, outlen);
}

/* This function finalizes a cipher context. */
int encryptFinal(ENCRYPT_CONTEXT* ctx, unsigned char* out, size_t* outlen)
{
    /* Finalize the context. */
    if (ctx->direction) return ctx->mode->fEncryptFinal(ctx, out, outlen);
    else return ctx->mode->fDecryptFinal(ctx, out, outlen);
}

/* This function frees an initialized encryption context. */
void encryptFree(ENCRYPT_CONTEXT* ctx)
{
    /* Free the context. */
    ctx->mode->fFree(ctx);
    sfree(ctx, sizeof(ENCRYPT_CONTEXT));
}
