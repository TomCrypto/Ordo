#include "testenv.h"

#define MAX_TESTS 1024

static size_t test_index;
static TEST tests[MAX_TESTS];

void register_test(TEST test)
{
    tests[test_index++] = test;
}

size_t test_count(void)
{
    return test_index;
}

TEST test(size_t index)
{
    return tests[index];
}

/* When adding a test, include the relevant header below and add each separate
 * test by using the register_test function. Please do not printf in tests. */

/* These are tests concerning library utilities i.e. not related to crypto. */
#include "tests/utility/errors.h"
#include "tests/utility/utils.h"
#include "tests/utility/mem.h"

/* This is for the OS-provided CSPRNG. */
#include "tests/misc/os_random.h"

/* This tests the digest interface and all hash functions. */
#include "tests/digest/digest.h"
#include "tests/hmac/hmac.h"
#include "tests/pbkdf2/pbkdf2.h"

#include "tests/stream/stream.h"
#include "tests/block/block.h"
#include "tests/block_modes/block_modes.h"

int register_all_tests(void)
{
    srand((unsigned)time(0)); /* For tests which need to use randomness. */

    register_test(test_mem);
    register_test(test_os_random);
    register_test(test_error_codes);
    register_test(test_macros);
    register_test(test_pad_check);
    register_test(test_xor_buffer);
    register_test(test_inc_buffer);
    register_test(test_digest);
    register_test(test_digest_utilities);
    register_test(test_hmac);
    register_test(test_pbkdf2);
    register_test(test_stream);
    register_test(test_stream_utilities);
    register_test(test_block);
    register_test(test_block_utilities);
    register_test(test_block_modes);
    register_test(test_block_modes_utilities);

    return 0; /* All tests registered. */
}

void hex(FILE *ext, const unsigned char *buffer, size_t len)
{
    if (ext)
    {
        size_t t;
        for (t = 0; t < len; ++t) fprintf(ext, "%02x", buffer[t]);
    }
}
