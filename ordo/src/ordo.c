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
int ordoEncrypt(unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen, CIPHER_PRIMITIVE* primitive, ENCRYPT_MODE* mode, void* key, size_t keySize, void* iv, void* cipherParams, void* modeParams)
{
    int error;
    size_t outPos = 0;

    /* Create the context. */
    ENCRYPTION_CONTEXT* ctx = encryptCreate(primitive, mode);
    if (!ctx) return ORDO_EHEAPALLOC;

    /* Initialize it. */
    error = encryptInit(ctx, key, keySize, iv, cipherParams, modeParams, 1);
    if (error < 0) return error;

    /* Encrypt the buffer. */
    encryptUpdate(ctx, in, inlen, out, outlen);
    outPos += *outlen;

    /* Finalize the context. */
    error = encryptFinal(ctx, out + outPos, outlen);
    if (error < 0) return error;
    *outlen += outPos;

    /* Free it and return success. */
    encryptFree(ctx);
    return ORDO_ESUCCESS;
}

/* This convenience function decrypts a buffer with a given key, tweak and IV. */
int ordoDecrypt(unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen, CIPHER_PRIMITIVE* primitive, ENCRYPT_MODE* mode, void* key, size_t keySize, void* iv, void* cipherParams, void* modeParams)
{
    int error;
    size_t outPos = 0;

    /* Create the context. */
    ENCRYPTION_CONTEXT* ctx = encryptCreate(primitive, mode);
    if (!ctx) return ORDO_EHEAPALLOC;

    /* Initialize it. */
    error = encryptInit(ctx, key, keySize, iv, cipherParams, modeParams, 0);
    if (error < 0) return error;

    /* Decrypt the buffer. */
    encryptUpdate(ctx, in, inlen, out, outlen);
    outPos += *outlen;

    /* Finalize the context. */
    error = encryptFinal(ctx, out + outPos, outlen);
    if (error < 0) return error;
    *outlen += outPos;

    /* Free it and return success. */
    encryptFree(ctx);
    return ORDO_ESUCCESS;
}
