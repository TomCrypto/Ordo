#include <ordo.h>

/* Load Ordo. */
void ordoLoad()
{
    /* Load all cryptographic primitives. */
    primitivesLoad();

    /* Load all encryption modes of operation. */
    encryptLoad();
}

/* This convenience function encrypts or decrypts a buffer with a given key, tweak and IV. */
int ordoEncrypt(unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen, BLOCK_CIPHER* primitive, BLOCK_CIPHER_MODE* mode, void* key, size_t keySize, void* iv, void* cipherParams, void* modeParams)
{
    int error;
    size_t outPos = 0;

    /* Create the context. */
    ENC_BLOCK_CIPHER_CONTEXT* ctx = encBlockCipherCreate(primitive, mode);
    if (!ctx) return ORDO_EHEAPALLOC;

    /* Initialize it. */
    error = encBlockCipherInit(ctx, key, keySize, iv, cipherParams, modeParams, 1);
    if (error < 0) return error;

    /* Encrypt the buffer. */
    encBlockCipherUpdate(ctx, in, inlen, out, outlen);
    outPos += *outlen;

    /* Finalize the context. */
    error = encBlockCipherFinal(ctx, out + outPos, outlen);
    if (error < 0) return error;
    *outlen += outPos;

    /* Free it and return success. */
    encBlockCipherFree(ctx);
    return ORDO_ESUCCESS;
}

/* This convenience function decrypts a buffer with a given key, tweak and IV. */
int ordoDecrypt(unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen, BLOCK_CIPHER* primitive, BLOCK_CIPHER_MODE* mode, void* key, size_t keySize, void* iv, void* cipherParams, void* modeParams)
{
    int error;
    size_t outPos = 0;

    /* Create the context. */
    ENC_BLOCK_CIPHER_CONTEXT* ctx = encBlockCipherCreate(primitive, mode);
    if (!ctx) return ORDO_EHEAPALLOC;

    /* Initialize it. */
    error = encBlockCipherInit(ctx, key, keySize, iv, cipherParams, modeParams, 0);
    if (error < 0) return error;

    /* Decrypt the buffer. */
    encBlockCipherUpdate(ctx, in, inlen, out, outlen);
    outPos += *outlen;

    /* Finalize the context. */
    error = encBlockCipherFinal(ctx, out + outPos, outlen);
    if (error < 0) return error;
    *outlen += outPos;

    /* Free it and return success. */
    encBlockCipherFree(ctx);
    return ORDO_ESUCCESS;
}

/* This convenience function encrypts or decrypts a buffer with a given key, tweak and IV. */
int ordoEncryptStream(unsigned char* inout, size_t len, STREAM_CIPHER* primitive, void* key, size_t keySize, void* cipherParams)
{
    int error;

    /* Create the context. */
    ENC_STREAM_CIPHER_CONTEXT* ctx = encStreamCipherCreate(primitive);
    if (!ctx) return ORDO_EHEAPALLOC;

    /* Initialize it. */
    error = encStreamCipherInit(ctx, key, keySize, cipherParams);
    if (error < 0) return error;

    /* Encrypt the buffer. */
    encStreamCipherUpdate(ctx, inout, len);

    /* Free it and return success. */
    encStreamCipherFree(ctx);
    return ORDO_ESUCCESS;
}

/* This convenience function decrypts a buffer with a given key, tweak and IV. */
int ordoDecryptStream(unsigned char* inout, size_t len, STREAM_CIPHER* primitive, void* key, size_t keySize, void* cipherParams)
{
    int error;

    /* Create the context. */
    ENC_STREAM_CIPHER_CONTEXT* ctx = encStreamCipherCreate(primitive);
    if (!ctx) return ORDO_EHEAPALLOC;

    /* Initialize it. */
    error = encStreamCipherInit(ctx, key, keySize, cipherParams);
    if (error < 0) return error;

    /* Decrypt the buffer. */
    encStreamCipherUpdate(ctx, inout, len);

    /* Free it and return success. */
    encStreamCipherFree(ctx);
    return ORDO_ESUCCESS;
}
