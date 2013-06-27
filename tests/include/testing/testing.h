#ifndef testing_h
#define testing_h

/**
 * @file testing.h
 *
 * \brief Ordo test driver interface.
 *
 * This is the interface to the Ordo test driver, which features a simplistic test vector script language, and functions to parse it.
 *
 * @see testing.c
 */

/* Ordo includes. */
#include <ordo.h>

/* Standard includes. */
#include <stdio.h>
#include <time.h>

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

/*! Tests the random module by generating a few pseudorandom bytes. Outputs results to stdout. */
void randomTest();

#endif
