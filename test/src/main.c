#include <ordo.h>
#include <testing/testing.h>
#include <common/ordotypes.h>

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
    /* Use a 128MB buffer size in performance tests to get decent resolution. */
    #define BUFSIZE (1024 * 1024 * 128)
    unsigned char* buffer = malloc(BUFSIZE);
    if (buffer == 0)
    {
        printf("[!] Could not allocate buffer memory.\n\n");
        return;
    }

    /* Test some cipher primitives & encryption modes. */
    encryptPerformance(Threefish256(), ECB(), 32, buffer, BUFSIZE);
    encryptPerformance(Threefish256(), CBC(), 32, buffer, BUFSIZE);
    encryptPerformance(Threefish256(), CTR(), 32, buffer, BUFSIZE);
    encryptPerformance(Threefish256(), CFB(), 32, buffer, BUFSIZE);
    encryptPerformance(Threefish256(), OFB(), 32, buffer, BUFSIZE);
    encryptPerformance(RC4(), STREAM(), 32, buffer, BUFSIZE);

    /* Free the buffer used for tests. */
    free(buffer);
}

int main(int argc, char* argv[])
{
    /* Display a little header with version information. */
    printf("[+] Ordo v%s (%s | %s).\n", ordoBuildInfo()->version, ordoBuildInfo()->build, ordoBuildInfo()->devtag);
    printf("[+] Built for %d-bit %s (%s).\n", ordoBuildInfo()->wordSize, ordoBuildInfo()->platform, ordoBuildInfo()->ABI);
    printf("\n");

    /* Initialize Ordo. */
    ordoLoad();

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
    printf("[+] All operations completed.\n");
    return 0;
}
