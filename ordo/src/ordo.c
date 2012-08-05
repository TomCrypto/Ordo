#include <primitives/primitives.h>
#include <encrypt/encrypt.h>
#include <ordo.h>

/* Load Ordo. */
void loadOrdo()
{
    /* Load all cryptographic primitives. */
    loadPrimitives();

    /* Load all encryption modes of operation. */
    loadEncryptModes();
}

/* Unload Ordo. */
void unloadOrdo()
{
    /* Unload all encryption modes of operation. */
    unloadEncryptModes();

    /* Unload all cryptographic primitives. */
    unloadPrimitives();
}

/* This convenience function encrypts or decrypts a buffer with a given key, tweak and IV. */
int ordoEncrypt(unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen, CIPHER_PRIMITIVE* primitive, ENCRYPT_MODE* mode, void* key, size_t keySize, void* tweak, void* iv, int padding)
{
    int error;
    size_t total = 0;

    ENCRYPT_CONTEXT* ctx = encryptCreate(primitive, mode, 1, padding);

    error = encryptInit(ctx, key, keySize, tweak, iv);
    if (error < 0) return error;

    encryptUpdate(ctx, in, inlen, out, outlen);
    total += *outlen;

    error = encryptFinal(ctx, out + *outlen, outlen);
    if (error < 0) return error;
    total += *outlen;

    encryptFree(ctx);
    *outlen = total;

    return ORDO_ESUCCESS;

    /* The code below feeds the buffer to Ordo by packets of random size (from 0 to 15 bytes). Obviously, it is much slower, but it is an excellent resilience and stability test. */

    /*
    size_t t;
    size_t fed = 0;
    size_t total = 0;
    ENCRYPT_CONTEXT* ctx = encryptCreate(primitive, mode, 1, padding);
    if (encryptInit(ctx, key, keySize, tweak, iv)) return ORDO_EFAIL;

    while (fed < inlen)
    {
        t = rand() % 16;
        if (t > inlen - fed) t = inlen - fed;

    	encryptUpdate(ctx, in + fed, t, out + total, outlen);
    	total += *outlen;
    	fed += t;
    }

    if (encryptFinal(ctx, out + total, outlen)) return ORDO_EFAIL;
    total += *outlen;
    encryptFree(ctx);
    *outlen = total;
    return ORDO_SUCCESS;
    */
}

/* This convenience function decrypts a buffer with a given key, tweak and IV. */
int ordoDecrypt(unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen, CIPHER_PRIMITIVE* primitive, ENCRYPT_MODE* mode, void* key, size_t keySize, void* tweak, void* iv, int padding)
{
    int error;
    size_t total = 0;

    ENCRYPT_CONTEXT* ctx = encryptCreate(primitive, mode, 0, padding);

    error = encryptInit(ctx, key, keySize, tweak, iv);
    if (error < 0) return error;

    encryptUpdate(ctx, in, inlen, out, outlen);
    total += *outlen;

    error = encryptFinal(ctx, out + *outlen, outlen);
    if (error < 0) return error;
    total += *outlen;

    encryptFree(ctx);
    *outlen = total;

    return ORDO_ESUCCESS;

    /*
    size_t t;
    size_t fed = 0;
    size_t total = 0;
    ENCRYPT_CONTEXT* ctx = encryptCreate(primitive, mode, 0, padding);
    if (encryptInit(ctx, key, keySize, tweak, iv)) return ORDO_EFAIL;

    while (fed < inlen)
    {
        t = rand() % 16;
        if (t > inlen - fed) t = inlen - fed;

    	encryptUpdate(ctx, in + fed, t, out + total, outlen);
    	total += *outlen;
    	fed += t;
    }

    if (encryptFinal(ctx, out + total, outlen)) return ORDO_EFAIL;
    total += *outlen;
    encryptFree(ctx);
    *outlen = total;
    return ORDO_SUCCESS;
    */
}
