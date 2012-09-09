#include <ordo.h>
#include <testing/testing.h>
#include <common/ordotypes.h>

int main(int argc, char* argv[])
{
    /* Use a 128MB buffer size in performance tests to get decent resolution. */
    #define BUFSIZE (1024 * 1024 * 128)
    unsigned char* buffer;

    /* The test vector file. */
    FILE* vectors;

    /* Display environment info. */
    envOrdo(stdout);

    /* Initialize Ordo. */
    loadOrdo();

    /* First of all, get the CSPRNG test out of the way. */
    printf("-------- Tests for the random module --------\n\n");
    randomTest();

    /* Open the test vector file. */
    printf("-------- Test vectors --------\n\n");
    vectors = loadTestVectors("vectors");
    if (vectors == 0) printf("[!] Could not load test vectors, skipping tests...\n\n");
    else
    {
        /* Run the test vectors then close the test vector file. */
        runTestVectors(vectors);
        unloadTestVectors(vectors);
    }

    /* Evaluate performance of relevant ciphers and modes. */
    printf("-------- Performance tests for the encrypt module --------\n\n");

    /* Allocate a large buffer to store plaintext/ciphertext. */
    buffer = malloc(BUFSIZE);

    /* Test some cipher primitives & encryption modes. */
    encryptPerformance(Threefish256(), ECB(), 32, buffer, BUFSIZE);
    encryptPerformance(Threefish256(), CBC(), 32, buffer, BUFSIZE);
    encryptPerformance(Threefish256(), CTR(), 32, buffer, BUFSIZE);
    encryptPerformance(Threefish256(), CFB(), 32, buffer, BUFSIZE);
    encryptPerformance(Threefish256(), OFB(), 32, buffer, BUFSIZE);
    encryptPerformance(RC4(), STREAM(), 32, buffer, BUFSIZE);

    /* Free the buffer used for tests. */
    free(buffer);

    /* Do user input once. */
    printf("-------- User input test --------\n\n");
    encryptUserInput();

    /* Finalize Ordo. */
    unloadOrdo();
    printf("\n[+] All operations completed.\n");
    return 0;
}
