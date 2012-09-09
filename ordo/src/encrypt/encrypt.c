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

/* Mode of operation list. */
ENCRYPT_MODE* _ECB;
ENCRYPT_MODE* _CBC;
ENCRYPT_MODE* _CTR;
ENCRYPT_MODE* _CFB;
ENCRYPT_MODE* _OFB;
ENCRYPT_MODE* _STREAM;

/* Loads all cipher modes. */
void encryptLoad()
{
    _ECB = malloc(sizeof(ENCRYPT_MODE));
    ECB_SetMode(_ECB);

    _CBC = malloc(sizeof(ENCRYPT_MODE));
    CBC_SetMode(_CBC);

    _CTR = malloc(sizeof(ENCRYPT_MODE));
    CTR_SetMode(_CTR);

    _CFB = malloc(sizeof(ENCRYPT_MODE));
    CFB_SetMode(_CFB);

    _OFB = malloc(sizeof(ENCRYPT_MODE));
    OFB_SetMode(_OFB);

    _STREAM = malloc(sizeof(ENCRYPT_MODE));
    STREAM_SetMode(_STREAM);
}

/* Unloads all cipher modes. */
void encryptUnload()
{
    free(_ECB);
    free(_CBC);
    free(_CTR);
    free(_CFB);
    free(_OFB);
    free(_STREAM);
}

/* Pass-through functions to acquire modes of operation. */
ENCRYPT_MODE* ECB() { return _ECB; }
ENCRYPT_MODE* CBC() { return _CBC; }
ENCRYPT_MODE* CTR() { return _CTR; }
ENCRYPT_MODE* CFB() { return _CFB; }
ENCRYPT_MODE* OFB() { return _OFB; }
ENCRYPT_MODE* STREAM() { return _STREAM; }

/* Gets an encryption mode object from a name. */
ENCRYPT_MODE* getEncryptMode(char* name)
{
    /* Simply compare against the existing list. */
    if (strcmp(name, ECB()->name) == 0) return ECB();
    if (strcmp(name, CBC()->name) == 0) return CBC();
    if (strcmp(name, CTR()->name) == 0) return CTR();
    if (strcmp(name, CFB()->name) == 0) return CFB();
    if (strcmp(name, OFB()->name) == 0) return OFB();
    if (strcmp(name, STREAM()->name) == 0) return STREAM();
    return 0;
}

/* This function returns an initialized encryption context using a specific primitive and mode of operation.
 * Note this function uses a fall-through construction to ensure no memory is leaked in case of failure. */
ENCRYPTION_CONTEXT* encryptCreate(CIPHER_PRIMITIVE* primitive, ENCRYPT_MODE* mode)
{
    /* Allocate the encryption context. */
    ENCRYPTION_CONTEXT* ctx = salloc(sizeof(ENCRYPTION_CONTEXT));
    if (ctx)
    {
        /* Create the cipher context. */
        ctx->cipher = cipherCreate(primitive);
        if (ctx->cipher)
        {
            /* Allocate the mode context. */
            ctx->mode = salloc(sizeof(ENCRYPT_MODE_CONTEXT));
            if (ctx->mode)
            {
                /* Create the mode context. */
                mode->fCreate(ctx->mode, ctx->cipher);
                modeobj(ctx) = mode;

                /* Return the allocated context. */
                return ctx;
            } else sfree(ctx->mode, sizeof(ENCRYPT_MODE_CONTEXT));
        } else cipherFree(ctx->cipher);
    } else sfree(ctx, sizeof(ENCRYPTION_CONTEXT));

    /* Fail, return zero. */
    return 0;
}

/* This function returns an initialized encryption context with the provided parameters. */
int encryptInit(ENCRYPTION_CONTEXT* ctx, void* key, size_t keySize, void* iv, void* cipherParams, void* modeParams, int direction)
{
    /* Initialize the cipher context. */
    int error = cipherInit(ctx->cipher, key, keySize, cipherParams);
    if (error < ORDO_ESUCCESS) return error;

    /* Save the required direction. */
    ctx->mode->direction = direction;

    /* Initialize the cipher context. */
    return modeobj(ctx)->fInit(ctx->mode, ctx->cipher, iv, modeParams);
}

/* This function encrypts data using the passed encryption context. If decrypt is true, the cipher will decrypt instead. */
void encryptUpdate(ENCRYPTION_CONTEXT* ctx, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
{
    /* Encrypt or decrypt the buffer. */
    if (ctx->mode->direction) modeobj(ctx)->fEncryptUpdate(ctx->mode, ctx->cipher, in, inlen, out, outlen);
    else modeobj(ctx)->fDecryptUpdate(ctx->mode, ctx->cipher, in, inlen, out, outlen);
}

/* This function finalizes a encryption context. */
int encryptFinal(ENCRYPTION_CONTEXT* ctx, unsigned char* out, size_t* outlen)
{
    /* Finalize the mode of operation. */
    return (ctx->mode->direction) ? modeobj(ctx)->fEncryptFinal(ctx->mode, ctx->cipher, out, outlen) : modeobj(ctx)->fDecryptFinal(ctx->mode, ctx->cipher, out, outlen);
}

/* This function frees an initialized encryption context. */
void encryptFree(ENCRYPTION_CONTEXT* ctx)
{
    /* Free the mode. */
    modeobj(ctx)->fFree(ctx->mode, ctx->cipher);
    sfree(ctx->mode, sizeof(ENCRYPT_MODE_CONTEXT));

    /* Free the cipher. */
    cipherFree(ctx->cipher);

    /* Free the context. */
    sfree(ctx, sizeof(ENCRYPTION_CONTEXT));
}
