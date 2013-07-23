#ifndef TEST_UTILS_H
#define TEST_UTILS_H

#include <testenv.h>

int test_macros(char *output, size_t maxlen, FILE *ext);

int test_pad_check(char *output, size_t maxlen, FILE *ext);

int test_xor_buffer(char *output, size_t maxlen, FILE *ext);

int test_inc_buffer(char *output, size_t maxlen, FILE *ext);

#endif
