#include <stdio.h>
#include <time.h>
#include <ordo.h>

/* Prints a buffer byte per byte. */
void hex(void* input, size_t len)
{
    size_t t;
    for (t = 0; t < len; t++) printf("%.2x", *((unsigned char*)input + t));
}

/* Returns a readable error message. */
char* errorMsg(int code)
{
    /* Get a proper error message. */
    switch (code)
    {
        case ORDO_EFAIL: return "An external error occurred";
        case ORDO_EKEYSIZE: return "The key size is invalid";
        case ORDO_EPADDING: return "The padding block cannot be recognized";
        case ORDO_LEFTOVER: return "There is leftover input data";
    }

    /* Invalid error code... */
    return "Unknown error code";
}

void testPrimitiveMode(CIPHER_PRIMITIVE* primitive, ENCRYPT_MODE* mode, size_t size, size_t keySize, int padding)
{
    /* Declare variables. */
    int error;
    void* in;
    void* out;
    void* iv;
    void* key;
    size_t pad;

    /* Store the size and pad it up to the block size (this is only needed for ECB/CBC/etc... but it will be ignored for streaming modes, the extra space will simply be disregarded by the API) */
    if (size % primitiveBlockSize(primitive) == 0) pad = size + primitiveBlockSize(primitive);
    else pad = size + primitiveBlockSize(primitive) - size % primitiveBlockSize(primitive);

    /* Allocate a plaintext buffer and fill it with 0x77 bytes.*/
    in = malloc(size);
    memset(in, 0x77, size);

    /* Allocate a ciphertext buffer.*/
    out = malloc(pad);

    /* Allocate a buffer of the right size (= cipher block size) and fill it with 0xAA. */
    iv = malloc(primitiveBlockSize(primitive));
    memset(iv, 0xAA, primitiveBlockSize(primitive));

    /* Allocate a key of the right size, and fill it with 0xEE. */
    key = malloc(keySize);
    memset(key, 0xEE, keySize);

    /* Print data BEFORE encryption. */
    printf("Cipher: %s | Mode: %s (key length = %zu bits)\n", primitiveName(primitive), modeName(mode), keySize * 8);
    printf("Plaintext  : ");
    hex(in, size);
    printf(" (%zu bytes)\n", size);

    /* Encrypt. */
    error = ordoEncrypt((unsigned char*)in, size, (unsigned char*)out, &size, primitive, mode, key, keySize, 0, iv, padding);
    if (error < 0) printf("Ciphertext : Failed [%s] \n", errorMsg(error));
    else
    {
        /* Print data AFTER encryption. */
        printf("Ciphertext : ");
        hex(out, size);
        printf(" (%zu bytes)\n", size);

        /* Decrypt. */
        error = ordoDecrypt((unsigned char*)out, size, (unsigned char*)in, &size, primitive, mode, key, keySize, 0, iv, padding);
        if (error < 0) printf("Plaintext  : Failed [%s] \n", errorMsg(error));
        else
        {
            /* Print data AFTER decryption. */
            printf("Plaintext  : ");
            hex(in, size);
            printf(" (%zu bytes)\n", size);
        }
    }

    printf("\n---\n\n");

    /* Clean up. */
    free(key);
    free(iv);
    free(in);
    free(out);
}

/* Clears a buffer with a pseudorandom integer pattern. */
void randomize(unsigned char* buffer, size_t len)
{
    /* Get a 256-bit pseudorandom key and IV. */
    int error;
    size_t outlen;
    void* key = salloc(32);
    void* iv = salloc(32);
    error = ordoRandom((unsigned char*)key, 32);
    if (error != 0) printf("ordoRandom Failed [%s] !\n", errorMsg(error));
    error = ordoRandom((unsigned char*)iv, 32);
    if (error != 0) printf("ordoRandom Failed [%s] !\n", errorMsg(error));

    /* Encrypt the buffer with Threefish-256/OFB using this key and IV! */
    error = ordoEncrypt(buffer, len, buffer, &outlen, Threefish256, OFB, key, 32, 0, iv, 0);
    if (error != 0) printf("ordoEncrypt FAILED [%s]\n", errorMsg(error));

    /* Free the key and IV. */
    sfree(key, 32);
    sfree(iv, 32);
}

void ratePrimitiveMode(CIPHER_PRIMITIVE* primitive, ENCRYPT_MODE* mode, size_t keySize)
{
    /* Buffer size. */
    #define BUFSIZE (1024 * 1024 * 256)

    /* Declare variables. */
    int error;
    void* in;
    void* out;
    void* iv;
    void* key;
    size_t outlen;
    clock_t start;
    float time;

    /* Allocate a large plaintext buffer and randomize it. */
    in = malloc(BUFSIZE);
    randomize(in, BUFSIZE);

    /* Allocate a ciphertext buffer (also randomize it, because of lazy memory allocation). */
    out = malloc(BUFSIZE);
    randomize(out, BUFSIZE);

    /* Allocate a buffer of the right size (= cipher block size) and randomize it. */
    iv = malloc(primitiveBlockSize(primitive));
    randomize(iv, primitiveBlockSize(primitive));

    /* Allocate a key of the right size, and randomize it */
    key = malloc(keySize);
    randomize(key, keySize);

    /* Print primitive/mode information. */
    printf("Cipher: %s | Mode: %s (key length = %zu bits)\n", primitiveName(primitive), modeName(mode), keySize * 8);
    printf("Starting performance test...\n");

    /* Save starting time. */
    start = clock();

    /* Encrypt. */
    error = ordoEncrypt((unsigned char*)in, BUFSIZE, (unsigned char*)out, &outlen, primitive, mode, key, keySize, 0, iv, 0);
    if (error < 0) printf("An error occurred during encryption [%s].", errorMsg(error));
    else
    {
        /* Get total time and display speed. */
        start = clock() - start;
        time = (float)start / (float)CLOCKS_PER_SEC;
        printf("It took %.2f seconds to encrypt %dMB - Rated speed at %.1fMB/s.\n", time, BUFSIZE >> 20, (float)(BUFSIZE >> 20) / time);

        /* Reset the buffers to prevent caching from tainting the subsequent timings. */
        randomize(in, BUFSIZE);
        randomize(out, BUFSIZE);

        /* Save starting time. */
        start = clock();

        /* Decrypt. */
        error = ordoDecrypt((unsigned char*)in, BUFSIZE, (unsigned char*)out, &outlen, primitive, mode, key, keySize, 0, iv, 0);
        if (error < 0) printf("An error occurred during decryption [%s].", errorMsg(error));
        else
        {
            /* Get total time and display speed. */
            start = clock() - start;
            time = (float)start / (float)CLOCKS_PER_SEC;
            printf("It took %.2f seconds to decrypt %dMB - Rated speed at %.1fMB/s.\n", time, BUFSIZE >> 20, (float)(BUFSIZE >> 20) / time);
        }
    }

    printf("\n---\n\n");

    /* Clean up. */
    free(key);
    free(iv);
    free(in);
    free(out);
}

void csprngTest()
{
    /* Create a small 100-byte buffer. */
    size_t t;
    int error;
    void* buffer = malloc(100);

    /* Get random data, a few times. */
    printf("Generating random data...\n");
    for (t = 0; t < 31; t++)
    {
        error = ordoRandom(buffer, 100);
        if (error == 0) hex(buffer, 100);
        else printf("Error! [%s]", errorMsg(error));

        printf("\n");
    }
    printf("Generation complete.\n\n---\n\n");
}

int main(int argc, char* argv[])
{
	/* Print out debug/release info. */
	#if ORDO_DEBUG
	printf("# You are in debug mode!\n\n");
	#else
    printf("# You are in release (fast) mode!\n\n");
	#endif

    /* Print out environment information. */
    #if ENVIRONMENT_32
    printf("# 32-bit mode.\n");
    #else
    printf("# 64-bit mode.\n");
    #endif

    /* Print out platform information. */
    #if PLATFORM_LINUX
    printf("# Linux Platform.\n");
    #elif PLATFORM_WINDOWS
    printf("# Windows Platform.\n");
    #endif

    /* Print out ABI information. */
    #if ABI_LINUX_64
    printf("# 64-bit Linux calling convention.\n");
    #elif ABI_WINDOWS_64
    printf("# 64-bit Windows calling convention.\n");
    #elif ABI_CDECL
    printf("# Standard cdecl calling convention.\n");
    #endif

    /* Printf supported feature flags. */
    printf("# Feature flags: ");
    #if FEATURE_MMX
    printf("[MMX]");
    #endif
    #if FEATURE_SSE
    printf("[SSE]");
    #endif
    #if FEATURE_SSE2
    printf("[SSE2]");
    #endif
    #if FEATURE_SSE3
    printf("[SSE3]");
    #endif
    #if FEATURE_SSE4_1
    printf("[SSE4.1]");
    #endif
    #if FEATURE_SSE4_2
    printf("[SSE4.2]");
    #endif
    #if FEATURE_AVX
    printf("[AVX]");
    #endif
    #if FEATURE_AES
    printf("[AES]");
    #endif

    printf("\n\n");

    printf("Loading Ordo... ");
    loadOrdo();
    printf("Loaded!\n");

    printf("\n---\n\n");
    printf("* STARTING ENCRYPTION TESTS...\n\n---\n\n");

    testPrimitiveMode(NullCipher, ECB, 11, 19, 1);
    testPrimitiveMode(NullCipher, CBC, 44, 19, 1);
    testPrimitiveMode(NullCipher, CTR, 19, 44, 0);
    testPrimitiveMode(NullCipher, OFB, 17, 23, 0);
    testPrimitiveMode(NullCipher, CFB, 41, 23, 0);
    testPrimitiveMode(Threefish256, ECB, 64, 32, 1);
    testPrimitiveMode(Threefish256, CBC, 61, 32, 1);
    testPrimitiveMode(Threefish256, CTR, 57, 32, 0);
    testPrimitiveMode(Threefish256, OFB, 61, 32, 0);
    testPrimitiveMode(Threefish256, CFB, 59, 32, 0);
    testPrimitiveMode(RC4, STREAM, 39, 41, 0);

    printf("* STARTING PERFORMANCE TESTS...\n\n---\n\n");

    ratePrimitiveMode(NullCipher, ECB, 16);
    ratePrimitiveMode(NullCipher, CBC, 16);
    ratePrimitiveMode(NullCipher, CTR, 16);
    ratePrimitiveMode(NullCipher, OFB, 16);
    ratePrimitiveMode(NullCipher, CFB, 16);
    ratePrimitiveMode(Threefish256, ECB, 32);
    ratePrimitiveMode(Threefish256, CBC, 32);
    ratePrimitiveMode(Threefish256, CTR, 32);
    ratePrimitiveMode(Threefish256, OFB, 32);
    ratePrimitiveMode(Threefish256, CFB, 32);
    ratePrimitiveMode(RC4, STREAM, 64);

    printf("* STARTING CSPRNG TEST...\n\n---\n\n");
    csprngTest();

    printf("Unloading Ordo... ");
    unloadOrdo();
    printf("Unloaded!\n\n");

    return 0;
}
