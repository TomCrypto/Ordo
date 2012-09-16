/* Handles code related to symmetric ciphers (e.g. modes of operation). */
#include <primitives/primitives.h>
#include <enc/enc_block.h>

/* Mode of operation list. */
#include <enc/block_cipher_modes/ecb.h>
#include <enc/block_cipher_modes/cbc.h>
#include <enc/block_cipher_modes/ctr.h>
#include <enc/block_cipher_modes/cfb.h>
#include <enc/block_cipher_modes/ofb.h>

/* Macro to the mode of operation object of an encryption context. */
#define modeobj(ctx) (ctx->mode->mode)

/* Macro to the cipher primitive object of an encryption context. */
#define cipherobj(ctx) (ctx->cipherCtx->cipher)

/* Encryption mode of operation list. */
BLOCK_CIPHER_MODE encryptModes[BLOCK_CIPHER_MODE_COUNT];

/* Loads all cipher modes. */
void encryptLoad()
{
    /* Initialize each encryption mode object. */
    ECB_SetMode   (&encryptModes[BLOCK_CIPHER_MODE_ECB]);
    CBC_SetMode   (&encryptModes[BLOCK_CIPHER_MODE_CBC]);
    CTR_SetMode   (&encryptModes[BLOCK_CIPHER_MODE_CTR]);
    CFB_SetMode   (&encryptModes[BLOCK_CIPHER_MODE_CFB]);
    OFB_SetMode   (&encryptModes[BLOCK_CIPHER_MODE_OFB]);
}

/* Pass-through functions to acquire modes of operation. */
BLOCK_CIPHER_MODE* ECB()    { return &encryptModes[BLOCK_CIPHER_MODE_ECB]; }
BLOCK_CIPHER_MODE* CBC()    { return &encryptModes[BLOCK_CIPHER_MODE_CBC]; }
BLOCK_CIPHER_MODE* CTR()    { return &encryptModes[BLOCK_CIPHER_MODE_CTR]; }
BLOCK_CIPHER_MODE* CFB()    { return &encryptModes[BLOCK_CIPHER_MODE_CFB]; }
BLOCK_CIPHER_MODE* OFB()    { return &encryptModes[BLOCK_CIPHER_MODE_OFB]; }

/* Gets an encryption mode object from a name. */
BLOCK_CIPHER_MODE* getBlockCipherModeByName(char* name)
{
    ssize_t t;
    for (t = 0; t < BLOCK_CIPHER_MODE_COUNT; t++)
    {
        /* Simply compare against the encryption mode list. */
        if (strcmp(name, encryptModes[t].name) == 0) return &encryptModes[t];
    }

    /* No match found. */
    return 0;
}

/* Returns an encryption mode object from an ID. */
BLOCK_CIPHER_MODE* getBlockCipherModeByID(size_t ID)
{
    return (ID < BLOCK_CIPHER_MODE_COUNT) ? &encryptModes[ID] : 0;
}

/* This function returns an initialized encryption mode context using a specific primitive. */
BLOCK_CIPHER_MODE_CONTEXT* block_cipher_mode_create(BLOCK_CIPHER_MODE* mode, BLOCK_CIPHER_CONTEXT* cipherCtx)
{
    /* Allocate the encryption mode context. */
    return mode->fCreate(mode, cipherCtx);
}

/* This function returns an initialized encryption mode context with the provided parameters. */
int block_cipher_mode_init(BLOCK_CIPHER_MODE_CONTEXT* modeCtx, BLOCK_CIPHER_CONTEXT* cipherCtx, void* iv, void* modeParams, int direction)
{
    /* Save the required direction. */
    modeCtx->direction = direction;

    /* Initialize the encryption mode context. */
    return modeCtx->mode->fInit(modeCtx, cipherCtx, iv, modeParams);
}

/* This function encrypts or decrypts a buffer with the encryption mode context. */
void block_cipher_mode_update(BLOCK_CIPHER_MODE_CONTEXT* modeCtx, BLOCK_CIPHER_CONTEXT* cipherCtx, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
{
    /* Encrypt or decrypt the buffer. */
    if (modeCtx->direction) modeCtx->mode->fEncryptUpdate(modeCtx, cipherCtx, in, inlen, out, outlen);
    else modeCtx->mode->fDecryptUpdate(modeCtx, cipherCtx, in, inlen, out, outlen);
}

/* This function finalizes an encryption mode context and returns any final data. */
int block_cipher_mode_final(BLOCK_CIPHER_MODE_CONTEXT* modeCtx, BLOCK_CIPHER_CONTEXT* cipherCtx, unsigned char* out, size_t* outlen)
{
    /* Finalize the mode of operation. */
    return (modeCtx->direction) ? modeCtx->mode->fEncryptFinal(modeCtx, cipherCtx, out, outlen) : modeCtx->mode->fDecryptFinal(modeCtx, cipherCtx, out, outlen);
}

/* This function frees an initialized encryption mode context. */
void block_cipher_mode_free(BLOCK_CIPHER_MODE_CONTEXT* modeCtx, BLOCK_CIPHER_CONTEXT* cipherCtx)
{
    /* Free the cipher context. */
    modeCtx->mode->fFree(modeCtx, cipherCtx);
}

/* This function returns an initialized encryption context using a specific primitive and mode of operation.
 * Note this function uses a fall-through construction to ensure no memory is leaked in case of failure. */
ENC_BLOCK_CONTEXT* enc_block_create(BLOCK_CIPHER* cipher, BLOCK_CIPHER_MODE* mode)
{
    /* Allocate the encryption context. */
    ENC_BLOCK_CONTEXT* ctx = salloc(sizeof(ENC_BLOCK_CONTEXT));
    if (ctx)
    {
        /* Create the cipher context. */
        if ((ctx->cipherCtx = block_cipher_create(cipher)))
        {
            /* Create the mode context. */
            if ((ctx->modeCtx = block_cipher_mode_create(mode, ctx->cipherCtx))) return ctx;
            block_cipher_free(ctx->cipherCtx);
        }
        sfree(ctx, sizeof(ENC_BLOCK_CONTEXT));
    };

    /* Fail, return zero. */
    return 0;
}

/* This function returns an initialized encryption context with the provided parameters. */
int enc_block_init(ENC_BLOCK_CONTEXT* ctx, void* key, size_t keySize, void* iv, void* cipherParams, void* modeParams, int direction)
{
    /* Initialize the cipher context. */
    int error = block_cipher_init(ctx->cipherCtx, key, keySize, cipherParams);
    if (error < ORDO_ESUCCESS) return error;

    /* Initialize the encryption mode context. */
    return block_cipher_mode_init(ctx->modeCtx, ctx->cipherCtx, iv, modeParams, direction);
}

/* This function encrypts data using the passed encryption context. If decrypt is true, the cipher will decrypt instead. */
void enc_block_update(ENC_BLOCK_CONTEXT* ctx, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
{
    block_cipher_mode_update(ctx->modeCtx, ctx->cipherCtx, in, inlen, out, outlen);
}

/* This function finalizes a encryption context. */
int enc_block_final(ENC_BLOCK_CONTEXT* ctx, unsigned char* out, size_t* outlen)
{
    return block_cipher_mode_final(ctx->modeCtx, ctx->cipherCtx, out, outlen);
}

/* This function frees an initialized encryption context. */
void enc_block_free(ENC_BLOCK_CONTEXT* ctx)
{
    /* Free the encryption mode context. */
    block_cipher_mode_free(ctx->modeCtx, ctx->cipherCtx);

    /* Free the cipher context. */
    block_cipher_free(ctx->cipherCtx);

    /* Free the context. */
    sfree(ctx, sizeof(ENC_BLOCK_CONTEXT));
}