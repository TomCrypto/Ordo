#include "../include/primitives.h"
#include "../include/encrypt.h"
#include "../include/ordo.h"

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

    /* The code below feeds the buffer byte by byte to Ordo. Obviously, it is much slower, but it is an excellent resilience and stability test.
       A possible improvement would be to feed the buffer by random increments of 1 to say 16 bytes, to mimic real world use (such as data trickling
       through a slow communication channel). Also possible to feed zero bytes, and see how it works. It should in theory work as all encryption
       modes are wrapped in a while (inlen != 0) loop which means encrypting or decrypting a null buffer is idempotent, as it should be. */

    /* size_t t;
    size_t total = 0;
    ENCRYPT_CONTEXT* ctx = encryptCreate(primitive, mode, 1, padding);
    if (encryptInit(ctx, key, keySize, tweak, iv)) return ORDO_EFAIL;

    for (t = 0; t < inlen; t++)
    {
    	encryptUpdate(ctx, in, 1, out + total, outlen);
    	total += *outlen;
    	in++;
    }

    if (encryptFinal(ctx, out + total, outlen)) return ORDO_EFAIL;
    total += *outlen;
    encryptFree(ctx);
    *outlen = total;
    return 0; */
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

    /* size_t t;
    size_t total = 0;
    ENCRYPT_CONTEXT* ctx = encryptCreate(primitive, mode, 0, padding);
    if (encryptInit(ctx, key, keySize, tweak, iv)) return ORDO_EFAIL;

    for (t = 0; t < inlen; t++)
    {
    	encryptUpdate(ctx, in, 1, out + total, outlen);
    	total += *outlen;
    	in++;
    }

    if (encryptFinal(ctx, out + total, outlen)) return ORDO_EFAIL;
    total += *outlen;
    encryptFree(ctx);
    *outlen = total;
    return 0; */
}
