#ifndef testing_h
#define testing_h

/**
 * @file testing.h
 * This is the interface to the Ordo test driver, which features a simplistic test vector script language, and functions to parse it.
 *
 * @see testing.c
 */

#include <ordo.h>
#include <common/ordotypes.h>

/*! This function prints out environment information to the standard output. This includes the platform on which the code is
    currently running, the word size (32/64 bit), the ABI in use (this is inferred) and CPU feature flags such as support for
    SSE instructions, AES-NI, etc... */
void displayEnvironmentInfo();

/*! Opens a test vector file.
    \param path The path of the test vector file to open.
    \return Returns a pointer to the opened file, or 0 on error. */
FILE* loadTestVectors(char* path);

/*! Runs every test vector in a specified test vector file.
    \param file The test vector file. */
void runTestVectors(FILE* file);

/*! Closes a test vector file.
    \param file The test vector file. */
void unloadTestVectors(FILE* file);

/*! Tests the random module by outputting a few pseudorandom bytes. */
void randomTest();

/*! Rates the performance of a cipher primitive/encryption mode combination.
    \param primitive The cipher primitive to use.
    \param mode The encryption mode to use.
    \param keySize The key size to use, in bytes.
    \param buffer A buffer to use to store the plaintext/ciphertexts.
    \param bufferSize The size, in bytes, of the buffer.
    \remark The bigger the storage buffer, the more accurate the performance reading, but the slower the function. */
void encryptPerformance(CIPHER_PRIMITIVE* primitive, ENCRYPT_MODE* mode, size_t keySize, unsigned char* buffer, size_t bufferSize);

#endif
