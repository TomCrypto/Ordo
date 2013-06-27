#include <testing/testing.h>

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

int main(int argc, char* argv[])
{
    /* Display a little header with version information. */
    printf("[+] Ordo version %d.%d.%d.\n", ordo_version_major(), ordo_version_minor(), ordo_version_rev());
    #ifdef ORDO_DEBUG
    printf("[+] Debug mode.\n");
    #endif
    printf("\n");

    /* Initialize Ordo. */
    ordo_init();

    /* First of all, get the CSPRNG test out of the way. */
    printf("-------- CSPRNG Tests --------\n\n");
    randomTest();

    /* Run the test vectors. */
    printf("-------- Test Vectors --------\n\n");
    testVectors();

    /* All done! */
    printf("[+] All operations completed.\n");
    return 0;
}
