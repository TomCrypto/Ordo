#ifndef testing_h
#define testing_h

/**
 * @file testing.h
 * This is the interface to the Ordo test driver, which features a simplistic test vector language, and functions to parse it.
 *
 * @see testing.c
 */

#include <ordo.h>
#include <common/ordotypes.h>

/* Prints out environment information. */
void displayEnvironmentInfo();

/* Opens the test vector file. */
FILE* loadTestVectors(char* path);

/* Runs all test vectors. */
void runTestVectors(FILE* file);

/* Closes the test vector file. */
void unloadTestVectors(FILE* file);

/* Performs a test of the random module. */
void randomTest();

/* Rates the performance of a cipher primitive/encryption mode combination. Uses an existing buffer. */
void encryptPerformance(CIPHER_PRIMITIVE* primitive, ENCRYPT_MODE* mode, size_t keySize, unsigned char* buffer, size_t bufferSize);

#endif
