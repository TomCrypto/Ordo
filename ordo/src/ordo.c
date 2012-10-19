#include <ordo.h>

/* Load Ordo. */
void ordoLoad()
{
    /* Load all cryptographic primitives. */
    primitivesLoad();

    /* Load all encryption modes of operation. */
    encryptLoad();
}

/* This convenience function encrypts a buffer with a given block cipher, key, IV, and parameters. */
int ordoEncrypt(unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen, BLOCK_CIPHER* primitive, BLOCK_CIPHER_MODE* mode, void* key, size_t keySize, void* iv, void* cipherParams, void* modeParams)
{
    int error;
    size_t outPos = 0;

    /* Create the context. */
    ENC_BLOCK_CIPHER_CONTEXT* ctx = encBlockCipherCreate(primitive, mode);
    if (!ctx) return ORDO_EHEAPALLOC;

    /* Initialize it. */
    error = encBlockCipherInit(ctx, key, keySize, iv, cipherParams, modeParams, 1);
    if (error == ORDO_ESUCCESS)
    {
        /* Encrypt the buffer. */
        encBlockCipherUpdate(ctx, in, inlen, out, outlen);
        outPos += *outlen;

        /* Finalize the context. */
        error = encBlockCipherFinal(ctx, out + outPos, outlen);
        if (error == ORDO_ESUCCESS) *outlen += outPos;
    }

    /* Free the context and return success or failure. */
    encBlockCipherFree(ctx);
    return error;
}

/* This convenience function decrypts a buffer with a given block cipher, key, IV, and parameters. */
int ordoDecrypt(unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen, BLOCK_CIPHER* primitive, BLOCK_CIPHER_MODE* mode, void* key, size_t keySize, void* iv, void* cipherParams, void* modeParams)
{
    int error;
    size_t outPos = 0;

    /* Create the context. */
    ENC_BLOCK_CIPHER_CONTEXT* ctx = encBlockCipherCreate(primitive, mode);
    if (!ctx) return ORDO_EHEAPALLOC;

    /* Initialize it. */
    error = encBlockCipherInit(ctx, key, keySize, iv, cipherParams, modeParams, 0);
    if (error == ORDO_ESUCCESS)
    {
        /* Encrypt the buffer. */
        encBlockCipherUpdate(ctx, in, inlen, out, outlen);
        outPos += *outlen;

        /* Finalize the context. */
        error = encBlockCipherFinal(ctx, out + outPos, outlen);
        if (error == ORDO_ESUCCESS) *outlen += outPos;
    }

    /* Free the context and return success or failure. */
    encBlockCipherFree(ctx);
    return error;
}

/* This convenience function encrypts or decrypts a buffer with a given stream cipher, key, IV, and parameters. */
int ordoEncryptStream(unsigned char* inout, size_t len, STREAM_CIPHER* primitive, void* key, size_t keySize, void* cipherParams)
{
    int error;

    /* Create the context. */
    ENC_STREAM_CIPHER_CONTEXT* ctx = encStreamCipherCreate(primitive);
    if (!ctx) return ORDO_EHEAPALLOC;

    /* Initialize it and encrypt the buffer. */
    error = encStreamCipherInit(ctx, key, keySize, cipherParams);
    if (error == ORDO_ESUCCESS) encStreamCipherUpdate(ctx, inout, len);

    /* Free the context and return success or failure. */
    encStreamCipherFree(ctx);
    return error;
}

/* Hashes a message. */
int ordoHash(unsigned char* in, size_t len, unsigned char* out, HASH_FUNCTION* hash, void* hashParams)
{
    int error;

    /* Create the context. */
    HASH_FUNCTION_CONTEXT* ctx = hashFunctionCreate(hash);
    if (!ctx) return ORDO_EHEAPALLOC;

    /* Initialize it. */
    error = hashFunctionInit(ctx, hashParams);
    if (error == ORDO_ESUCCESS)
    {
        /* Hash the buffer. */
        hashFunctionUpdate(ctx, in, len);

        /* Finalize the context. */
        hashFunctionFinal(ctx, out);
    }

    /* Free the context and return success or failure. */
    hashFunctionFree(ctx);
    return error;
}
