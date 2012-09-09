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

/* This function returns an initialized encryption mode context using a specific primitive. */
ENCRYPT_MODE_CONTEXT* encryptModeCreate(ENCRYPT_MODE* mode, CIPHER_PRIMITIVE_CONTEXT* cipher)
{
    /* Allocate the encryption mode context. */
    ENCRYPT_MODE_CONTEXT* ctx = salloc(sizeof(ENCRYPT_MODE_CONTEXT));
    if (ctx)
    {
        /* If the allocation succeeded, create the context. */
        ctx->mode = mode;
        mode->fCreate(ctx, cipher);
    }

    /* Return the context (allocated or not). */
    return ctx;
}

/* This function returns an initialized encryption mode context with the provided parameters. */
int encryptModeInit(ENCRYPT_MODE_CONTEXT* ctx, CIPHER_PRIMITIVE_CONTEXT* cipher, void* iv, void* modeParams, int direction)
{
    /* Save the required direction. */
    ctx->direction = direction;

    /* Initialize the encryption mode context. */
    return ctx->mode->fInit(ctx, cipher, iv, modeParams);
}

/* This function encrypts or decrypts a buffer with the encryption mode context. */
void encryptModeUpdate(ENCRYPT_MODE_CONTEXT* ctx, CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
{
    /* Encrypt or decrypt the buffer. */
    if (ctx->direction) ctx->mode->fEncryptUpdate(ctx, cipher, in, inlen, out, outlen);
    else ctx->mode->fDecryptUpdate(ctx, cipher, in, inlen, out, outlen);
}

/* This function finalizes an encryption mode context and returns any final data. */
int encryptModeFinal(ENCRYPT_MODE_CONTEXT* ctx, CIPHER_PRIMITIVE_CONTEXT* cipher, unsigned char* out, size_t* outlen)
{
    /* Finalize the mode of operation. */
    return (ctx->direction) ? ctx->mode->fEncryptFinal(ctx, cipher, out, outlen) : ctx->mode->fDecryptFinal(ctx, cipher, out, outlen);
}

/* This function frees an initialized encryption mode context. */
void encryptModeFree(ENCRYPT_MODE_CONTEXT* ctx, CIPHER_PRIMITIVE_CONTEXT* cipher)
{
    /* Free the cipher context. */
    ctx->mode->fFree(ctx, cipher);
    sfree(ctx, sizeof(ENCRYPT_MODE_CONTEXT));
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
            /* Create the mode context. */
            ctx->mode = encryptModeCreate(mode, ctx->cipher);
            if (ctx->mode) return ctx;
            cipherFree(ctx->cipher);
        }
        sfree(ctx, sizeof(ENCRYPTION_CONTEXT));
    };

    /* Fail, return zero. */
    return 0;
}

/* This function returns an initialized encryption context with the provided parameters. */
int encryptInit(ENCRYPTION_CONTEXT* ctx, void* key, size_t keySize, void* iv, void* cipherParams, void* modeParams, int direction)
{
    /* Initialize the cipher context. */
    int error = cipherInit(ctx->cipher, key, keySize, cipherParams);
    if (error < ORDO_ESUCCESS) return error;

    /* Initialize the encryption mode context. */
    return encryptModeInit(ctx->mode, ctx->cipher, iv, modeParams, direction);
}

/* This function encrypts data using the passed encryption context. If decrypt is true, the cipher will decrypt instead. */
void encryptUpdate(ENCRYPTION_CONTEXT* ctx, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
{
    encryptModeUpdate(ctx->mode, ctx->cipher, in, inlen, out, outlen);
}

/* This function finalizes a encryption context. */
int encryptFinal(ENCRYPTION_CONTEXT* ctx, unsigned char* out, size_t* outlen)
{
    return encryptModeFinal(ctx->mode, ctx->cipher, out, outlen);
}

/* This function frees an initialized encryption context. */
void encryptFree(ENCRYPTION_CONTEXT* ctx)
{
    /* Free the encryption mode context. */
    encryptModeFree(ctx->mode, ctx->cipher);

    /* Free the cipher context. */
    cipherFree(ctx->cipher);

    /* Free the context. */
    sfree(ctx, sizeof(ENCRYPTION_CONTEXT));
}
