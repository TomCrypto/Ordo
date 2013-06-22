#include <ordo.h>
#include <testing/testing.h>
#include <common/version.h>

/* Use a 256MB buffer size in performance tests to get decent resolution.
 * In debug mode, though, use only 64MB since everything is slower. */
#ifdef ORDO_DEBUG
    #define BUFSIZE (1024 * 1024 * 64)
#else
	#define BUFSIZE (1024 * 1024 * 256)
#endif

void testVectors()
{
    /* Open the test vector file. */
    FILE* vectors = loadTestVectors("vectors");
    if (vectors == 0) printf("[!] Could not load test vectors, skipping tests...\n\n");
    else
    {
        /* Run the test vectors then close the test vector file. */
        runTestVectors(vectors);
        unloadTestVectors(vectors);
    }
}

void performanceTest()
{
    unsigned char* buffer = malloc(BUFSIZE);
    if (buffer == 0)
    {
        printf("[!] Could not allocate buffer memory.\n\n");
        return;
    }

    /* Test some primitives performance-wise. */
    blockCipherPerformance(Threefish256(), ECB(), 32, buffer, BUFSIZE);
    blockCipherPerformance(Threefish256(), CBC(), 32, buffer, BUFSIZE);
    blockCipherPerformance(Threefish256(), CTR(), 32, buffer, BUFSIZE);
    blockCipherPerformance(Threefish256(), CFB(), 32, buffer, BUFSIZE);
    blockCipherPerformance(Threefish256(), OFB(), 32, buffer, BUFSIZE);
    blockCipherPerformance(AES(), ECB(), 16, buffer, BUFSIZE);
    blockCipherPerformance(AES(), CBC(), 16, buffer, BUFSIZE);
    blockCipherPerformance(AES(), CTR(), 16, buffer, BUFSIZE);
    blockCipherPerformance(AES(), CFB(), 16, buffer, BUFSIZE);
    blockCipherPerformance(AES(), OFB(), 16, buffer, BUFSIZE);
    streamCipherPerformance(RC4(), 32, buffer, BUFSIZE);
    hashFunctionPerformance(SHA256(), buffer, BUFSIZE);
    hashFunctionPerformance(MD5(), buffer, BUFSIZE);
    hashFunctionPerformance(Skein256(), buffer, BUFSIZE);
    pbkdf2Performance(SHA256(), 1000);
    pbkdf2Performance(SHA256(), 10000);
    pbkdf2Performance(SHA256(), 100000);
    pbkdf2Performance(Skein256(), 1000);
    pbkdf2Performance(Skein256(), 10000);
    pbkdf2Performance(Skein256(), 100000);

    /* Free the buffer used for tests. */
    free(buffer);
}

int main(int argc, char* argv[])
{
    /* Display a little header with version information. */
    printf("[+] Ordo version %d.%d.%d.\n", ordo_version_major(), ordo_version_minor(), ordo_version_rev());
	#ifdef ORDO_DEBUG
	printf("[+] Debug mode.\n");
	#endif
    printf("\n");

    /* Initialize Ordo. */
    load_ordo();

    /* First of all, get the CSPRNG test out of the way. */
    printf("-------- CSPRNG Tests --------\n\n");
    randomTest();

    /* Run the test vectors. */
    printf("-------- Test Vectors --------\n\n");
    testVectors();

    /* Evaluate performance of relevant ciphers and modes. */
    printf("-------- Performance Tests --------\n\n");
    performanceTest();

    /* All done! */
    printf("\n[+] All operations completed.\n");
    return 0;
}
