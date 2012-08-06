#include <stdio.h>
#include <time.h>
#include <ordo.h>
#include <testing/testing.h>

/* Prints a buffer byte per byte. */
void hex(void* input, size_t len)
{
    size_t t;
    for (t = 0; t < len; t++) printf("%.2x", *((unsigned char*)input + t));
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

/* Rates the performance of a primitive/mode combination. */
void ratePrimitiveMode(CIPHER_PRIMITIVE* primitive, ENCRYPT_MODE* mode, size_t keySize)
{
    /* Buffer size. */
    #define BUFSIZE (1024 * 1024 * 64)

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
    /* The test vector file. */
    FILE* vectors;

	/* Print out debug/release info. */
	#if ORDO_DEBUG
	printf("# Debug build.\n");
	#else
    printf("# Release build.\n");
	#endif

    /* Print out environment information. */
    #if ENVIRONMENT_32
    printf("# Environment: 32-bit.\n");
    #else
    printf("# Environment: 64-bit.\n");
    #endif

    /* Print out platform information. */
    #if PLATFORM_LINUX
    printf("# Platform: Linux.\n");
    #elif PLATFORM_WINDOWS
    printf("# Platform: Windows.\n");
    #endif

    /* Print out ABI information. */
    #if ABI_LINUX_64
    printf("# ABI: Linux x64.\n");
    #elif ABI_WINDOWS_64
    printf("# ABI: Windows x64.\n");
    #elif ABI_CDECL
    printf("# ABI: cdecl x86.\n");
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

    /* Load ordo. */
    printf("[.] Loading ordo...\n");
    loadOrdo();
    printf("[+] Loaded!\n");

    /* Open the test vector file. */
    printf("[.] Loading test vectors...\n");
    vectors = loadTestVectors();
    if (vectors == 0) printf("[!] Could not load test vectors, skipping tests...\n\n");
    else
    {
        /* Run the test vectors then close the test vector file. */
        printf("[+] Test vectors loaded, proceeding...\n\n");
        runTestVectors(vectors);
        unloadTestVectors(vectors);
    }

    /* Evaluate performance of relevant ciphers and modes. */
    printf("---\n\n");
    printf("* STARTING PERFORMANCE TESTS...\n\n---\n\n");

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
