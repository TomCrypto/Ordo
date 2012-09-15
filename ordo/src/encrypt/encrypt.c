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

/* Encryption mode of operation list. */
ENCRYPT_MODE encryptModes[ENCRYPT_MODE_COUNT];

/* Loads all cipher modes. */
void encryptLoad()
{
    /* Initialize each encryption mode object. */
    ECB_SetMode   (&encryptModes[ENCRYPT_MODE_ECB]);
    CBC_SetMode   (&encryptModes[ENCRYPT_MODE_CBC]);
    CTR_SetMode   (&encryptModes[ENCRYPT_MODE_CTR]);
    CFB_SetMode   (&encryptModes[ENCRYPT_MODE_CFB]);
    OFB_SetMode   (&encryptModes[ENCRYPT_MODE_OFB]);
    STREAM_SetMode(&encryptModes[ENCRYPT_MODE_STREAM]);
}

/* Pass-through functions to acquire modes of operation. */
ENCRYPT_MODE* ECB()    { return &encryptModes[ENCRYPT_MODE_ECB]; }
ENCRYPT_MODE* CBC()    { return &encryptModes[ENCRYPT_MODE_CBC]; }
ENCRYPT_MODE* CTR()    { return &encryptModes[ENCRYPT_MODE_CTR]; }
ENCRYPT_MODE* CFB()    { return &encryptModes[ENCRYPT_MODE_CFB]; }
ENCRYPT_MODE* OFB()    { return &encryptModes[ENCRYPT_MODE_OFB]; }
ENCRYPT_MODE* STREAM() { return &encryptModes[ENCRYPT_MODE_STREAM]; }

/* Gets an encryption mode object from a name. */
ENCRYPT_MODE* getEncryptModeByName(char* name)
{
    ssize_t t;
    for (t = 0; t < ENCRYPT_MODE_COUNT; t++)
    {
        /* Simply compare against the encryption mode list. */
        if (strcmp(name, encryptModes[t].name) == 0) return &encryptModes[t];
    }

    /* No match found. */
    return 0;
}

/* Returns an encryption mode object from an ID. */
ENCRYPT_MODE* getEncryptModeByID(size_t ID)
{
    return (ID < ENCRYPT_MODE_COUNT) ? &encryptModes[ID] : 0;
}

/* This function returns an initialized encryption mode context using a specific primitive. */
ENCRYPT_MODE_CONTEXT* encryptModeCreate(ENCRYPT_MODE* mode, CIPHER_PRIMITIVE_CONTEXT* cipher)
{
    /* Allocate the encryption mode context. */
    return mode->fCreate(mode, cipher);
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
        if ((ctx->cipher = cipherCreate(primitive)))
        {
            /* Create the mode context. */
            if ((ctx->mode = encryptModeCreate(mode, ctx->cipher))) return ctx;
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
