#include <ordo.h>
#include <testing/testing.h>

int main(int argc, char* argv[])
{
    /* The test vector file. */
    FILE* vectors;

    /* Display detected environment info. */
    displayEnvironmentInfo();

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

    /* Use a 128MB buffer size in performance tests to get decent resolution. */
    #define BUFSIZE (1024 * 1024 * 128)

    /* Allocate a large buffer to store plaintext/ciphertext. */
    unsigned char* buffer = malloc(BUFSIZE);

    /* Test some cipher primitives & encryption modes. */
    encryptPerformance(Threefish256, ECB, 32, buffer, BUFSIZE);
    encryptPerformance(Threefish256, CBC, 32, buffer, BUFSIZE);
    encryptPerformance(Threefish256, CTR, 32, buffer, BUFSIZE);
    encryptPerformance(Threefish256, OFB, 32, buffer, BUFSIZE);
    encryptPerformance(Threefish256, CFB, 32, buffer, BUFSIZE);
    encryptPerformance(RC4, STREAM, 64, buffer, BUFSIZE);

    /* Free the buffer used for tests. */
    free(buffer);

    /* Finalize Ordo. */
    unloadOrdo();
    printf("[+] All operations completed.");
    return 0;
}
