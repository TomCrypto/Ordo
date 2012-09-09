#include <ordo.h>

/* Load Ordo. */
void ordoLoad()
{
    /* Load all cryptographic primitives. */
    primitivesLoad();

    /* Load all encryption modes of operation. */
    encryptLoad();
}

/* Unload Ordo. */
void ordoUnload()
{
    /* Unload all encryption modes of operation. */
    encryptUnload();

    /* Unload all cryptographic primitives. */
    primitivesUnload();
}

/* Print information about the environment under which the library was built, to the specified file descriptor. */
void ordoEnv(FILE* out)
{
    /* First, find the platform. */
    #if PLATFORM_WINDOWS
    char* platform = "Windows";
    #elif PLATFORM_LINUX
    char* platform = "Linux";
    #endif

    /* Then, the environment. */
    #if ENVIRONMENT_64
    char* environment = "64-bit";
    #else
    char* environment = "32-bit";
    #endif

    /* Finally, the ABI. */
    #if ABI_LINUX_64
    char* ABI = "Linux x64";
    #elif ABI_WINDOWS_64
    char* ABI = "Windows x64";
    #elif ABI_CDECL
    char* ABI = "cdecl x86";
    #endif

    /* Print out the version, and whether we are in debug or release mode. */
    fprintf(out, "Ordo v1.0.2/");
	#if ORDO_DEBUG
	fprintf(out, "Debug.\n");
	#else
    fprintf(out, "Release.\n");
	#endif

    /* Print out this information. */
    fprintf(out, "Environment: %s, %s, %s.\n", platform, environment, ABI);

    /* Obtain the feature flags. */
    fprintf(out, "CPU features detected listed");
    #if FEATURE_MMX
    fprintf(out, ", MMX");
    #endif
    #if FEATURE_SSE
    fprintf(out, ", SSE");
    #endif
    #if FEATURE_SSE2
    fprintf(out, ", SSE2");
    #endif
    #if FEATURE_SSE3
    fprintf(out, ", SSE3");
    #endif
    #if FEATURE_SSE4_1
    fprintf(out, ", SSE4.1");
    #endif
    #if FEATURE_SSE4_2
    fprintf(out, ", SSE4.2");
    #endif
    #if FEATURE_AVX
    fprintf(out, ", AVX");
    #endif
    #if FEATURE_AES
    fprintf(out, ", AES");
    #endif

    /* All finished. */
    fprintf(out, ".\n\n");
}

/* This convenience function encrypts or decrypts a buffer with a given key, tweak and IV. */
int ordoEncrypt(unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen, CIPHER_PRIMITIVE* primitive, ENCRYPT_MODE* mode, void* key, size_t keySize, void* iv, void* cipherParams, void* modeParams)
{
    int error;
    size_t total = 0;

    ENCRYPTION_CONTEXT* ctx = encryptCreate(primitive, mode);

    error = encryptInit(ctx, key, keySize, iv, cipherParams, modeParams, 1);
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
    if (encryptInit(ctx, key, keySize, tweak, iv, 0)) return ORDO_EFAIL;

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
    return ORDO_ESUCCESS;
    */
}

/* This convenience function decrypts a buffer with a given key, tweak and IV. */
int ordoDecrypt(unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen, CIPHER_PRIMITIVE* primitive, ENCRYPT_MODE* mode, void* key, size_t keySize, void* iv, void* cipherParams, void* modeParams)
{
    int error;
    size_t total = 0;

    ENCRYPTION_CONTEXT* ctx = encryptCreate(primitive, mode);

    error = encryptInit(ctx, key, keySize, iv, cipherParams, modeParams, 0);
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
    if (encryptInit(ctx, key, keySize, tweak, iv, 0)) return ORDO_EFAIL;

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
    return ORDO_ESUCCESS;
    */
}
