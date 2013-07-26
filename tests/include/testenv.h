#ifndef TESTENV_H
#define TESTENV_H

#include <stdlib.h>
#include <stdint.h>
#include <limits.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#include "ordo.h"

/* A test returns 0 on failure, 1 on success. It can output stuff to a char
 * array passed as an argument, but without a newline (52 chars available).
 * It is also provided a file to write extended information, if needed.
 *
 * TEST GUIDELINES:
 * 1. if a test references something that doesn't exist yet in the library
 *    but may exist in the future, the test shall be assumed to pass, with
 *    a note in the extended log file that the test was skipped.
 * 2. if the library reports any error (including allocation errors), the
 *    test shall fail and the error be reported in the extended log file.
 * 3. a test shall terminate at the first error encountered. */
typedef int (*TEST)(char *output, size_t maxlen, FILE *ext);

/* Registers a particular test given a test function. */
void register_test(TEST test);

/* Returns the test function corresponding to a given test number. */
TEST test(size_t index);

/* Returns the number of tests registered so far. */
size_t test_count(void);

/* Registers all tests known to the test framework. */
int register_all_tests(void);

/* These are helpful macros to fail or pass tests. They assume the output
 * buffer is declared as "output", with maximum length "maxlen", as it is
 * by default. They only work with plain unformatted output strings. */
#define pass(str) { snprintf(output, maxlen, str); return 1; }
#define fail(str) { snprintf(output, maxlen, str); return 0; }

/* This will just return a random integer between 0 and N - 1. Note this is
 * biased but should be good enough for tests which just need to cover some
 * possible range of inputs. */
#define random(N) (rand() % N)

/* Prints the hexadecimal representation of a buffer to a file. */
void hex(FILE *ext, const unsigned char *buffer, size_t len);

/* A large scratch buffer to store calculation results. */
static unsigned char scratch[1024];

#endif
