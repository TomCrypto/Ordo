/* Handles code related to symmetric ciphers (e.g. modes of operation). */
#include <primitives/primitives.h>
#include <encrypt/encrypt.h>

/* Mode of operation list. */
#include <encrypt/modes/ecb.h>
#include <encrypt/modes/cbc.h>
#include <encrypt/modes/ctr.h>
#include <encrypt/modes/cfb.h>
#include <encrypt/modes/ofb.h>
#include <encrypt/modes/stream.h>

/* Macro to the mode of operation object of an encryption context. */
#define modeobj(ctx) (ctx->mode->mode)

/* Macro to the cipher primitive object of an encryption context. */
#define cipherobj(ctx) (ctx->cipher->primitive)

/* Loads all cipher modes. */
void loadEncryptModes()
{
    ECB = malloc(sizeof(ENCRYPT_MODE));
    ECB_SetMode(ECB);

    CBC = malloc(sizeof(ENCRYPT_MODE));
    CBC_SetMode(CBC);

    CTR = malloc(sizeof(ENCRYPT_MODE));
    CTR_SetMode(CTR);

    CFB = malloc(sizeof(ENCRYPT_MODE));
    CFB_SetMode(CFB);

    OFB = malloc(sizeof(ENCRYPT_MODE));
    OFB_SetMode(OFB);

    STREAM = malloc(sizeof(ENCRYPT_MODE));
    STREAM_SetMode(STREAM);
}

/* Unloads all cipher modes. */
void unloadEncryptModes()
{
    free(ECB);
    free(CBC);
    free(CTR);
    free(CFB);
    free(OFB);
    free(STREAM);
}

/* This function returns an initialized encryption context using a specific primitive and mode of operation. */
ENCRYPTION_CONTEXT* encryptCreate(CIPHER_PRIMITIVE* primitive, ENCRYPT_MODE* mode, int direction)
{
    /* Allocate the cipher and mode contexts. */
    ENCRYPTION_CONTEXT* ctx = salloc(sizeof(ENCRYPTION_CONTEXT));
    ctx->cipher =salloc(sizeof(CIPHER_PRIMITIVE_CONTEXT));
    ctx->mode = salloc(sizeof(ENCRYPT_MODE_CONTEXT));

    /* Create the cipher context. */
    primitive->fCreate(ctx->cipher);
    cipherobj(ctx) = primitive;

    /* Create the mode context. */
    mode->fCreate(ctx->mode, ctx->cipher);
    modeobj(ctx) = mode;

    /* Set context fields and return. */
    ctx->mode->direction = direction;
    return ctx;
}

/* This function returns an initialized cipher context with the provided parameters. */
int encryptInit(ENCRYPTION_CONTEXT* ctx, void* key, size_t keySize, void* iv, void* cipherParams, void* modeParams)
{
    /* Initialize the cipher context. */
    int error = cipherobj(ctx)->fInit(ctx->cipher, key, keySize, cipherParams);
    if (error < 0) return error;

    /* Initialize the cipher context. */
    return modeobj(ctx)->fInit(ctx->mode, ctx->cipher, iv, modeParams);
}

/* This function encrypts data using the passed cipher context. If decrypt is true, the cipher will decrypt instead. */
void encryptUpdate(ENCRYPTION_CONTEXT* ctx, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
{
    /* Encrypt or decrypt the buffer. */
    if (ctx->mode->direction) modeobj(ctx)->fEncryptUpdate(ctx->mode, ctx->cipher, in, inlen, out, outlen);
    else modeobj(ctx)->fDecryptUpdate(ctx->mode, ctx->cipher, in, inlen, out, outlen);
}

/* This function finalizes a cipher context. */
int encryptFinal(ENCRYPTION_CONTEXT* ctx, unsigned char* out, size_t* outlen)
{
    /* Finalize the context. */
    if (ctx->mode->direction) return modeobj(ctx)->fEncryptFinal(ctx->mode, ctx->cipher, out, outlen);
    else return modeobj(ctx)->fDecryptFinal(ctx->mode, ctx->cipher, out, outlen);
}

/* This function frees an initialized encryption context. */
void encryptFree(ENCRYPTION_CONTEXT* ctx)
{
    /* Free the mode. */
    modeobj(ctx)->fFree(ctx->mode, ctx->cipher);
    sfree(ctx->mode, sizeof(ENCRYPT_MODE_CONTEXT));

    /* Free the cipher. */
    cipherobj(ctx)->fFree(ctx->cipher);
    sfree(ctx->cipher, sizeof(CIPHER_PRIMITIVE_CONTEXT));

    /* Free the context. */
    sfree(ctx, sizeof(ENCRYPTION_CONTEXT));
}
