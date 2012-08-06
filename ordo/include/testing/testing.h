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

/* Opens the test vector file. */
FILE* loadTestVectors();

/* Runs all test vectors. */
void runTestVectors(FILE* file);

/* Closes the test vector file. */
void unloadTestVectors(FILE* file);

#endif
