#include "testenv.h"
#include <string.h>
#include "ordo.h"

struct TEST_VECTOR
{
    int primitive;
    size_t key_len;
    const char *key;
    size_t input_len;
    const char *input;
    const char *expected;
};

static struct TEST_VECTOR tests[] = {
{
    STREAM_RC4,
    5,
    "\x01\x02\x03\x04\x05",
    8,
    "\x01\x23\x45\x67\x89\xab\xcd\xef",
    "\xcd\x7b\x6a\xec\x20\x59\xa8\x0d"
},
{
    STREAM_RC4,
    16,
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    16,
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    "\xc3\x4b\x11\x6d\xa0\x18\xda\x7e\x4e\x07\x96\x53\x42\xbe\xcd\x64"
},
{
    STREAM_RC4,
    16,
    "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
    16,
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    "\x12\x84\xaa\x5c\xc4\xc6\x41\x9d\xf0\x3d\xae\xb9\xdd\xc6\xb4\x38"
},
{
    STREAM_RC4,
    16,
    "\x81\x94\xfe\x03\xff\x94\xe3\x81\xd0\xcc\x91\xb0\xaa\x9d\xe8\xf0",
    16,
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    "\xf4\xf6\x95\x08\x15\x32\xea\xd3\x40\x1f\xc5\x5a\x80\x99\xe0\x1d"
},
{
    STREAM_RC4,
    16,
    "\xff\x55\xff\x55\xff\x55\xff\x55\xff\x55\xff\x55\xff\x55\xff\x55",
    16,
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    "\xd1\x30\x52\xac\x16\x78\x92\x32\x9a\x32\x14\xf7\xc3\xaa\x7f\x09"
},
{
    STREAM_RC4,
    16,
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    16,
    "\x68\x65\x6c\x6c\x6f\x20\x64\x65\x61\x72\x20\x77\x6f\x72\x6c\x64",
    "\xab\x2e\x7d\x01\xcf\x38\xbe\x1b\x2f\x75\xb6\x24\x2d\xcc\xa1\x00"
},
{
    STREAM_RC4,
    16,
    "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
    16,
    "\x68\x65\x6c\x6c\x6f\x20\x64\x65\x61\x72\x20\x77\x6f\x72\x6c\x64",
    "\x7a\xe1\xc6\x30\xab\xe6\x25\xf8\x91\x4f\x8e\xce\xb2\xb4\xd8\x5c"
},
{
    STREAM_RC4,
    16,
    "\x81\x94\xfe\x03\xff\x94\xe3\x81\xd0\xcc\x91\xb0\xaa\x9d\xe8\xf0",
    16,
    "\x68\x65\x6c\x6c\x6f\x20\x64\x65\x61\x72\x20\x77\x6f\x72\x6c\x64",
    "\x9c\x93\xf9\x64\x7a\x12\x8e\xb6\x21\x6d\xe5\x2d\xef\xeb\x8c\x79"
},
{
    STREAM_RC4,
    16,
    "\xff\x55\xff\x55\xff\x55\xff\x55\xff\x55\xff\x55\xff\x55\xff\x55",
    16,
    "\x68\x65\x6c\x6c\x6f\x20\x64\x65\x61\x72\x20\x77\x6f\x72\x6c\x64",
    "\xb9\x55\x3e\xc0\x79\x58\xf6\x57\xfb\x40\x34\x80\xac\xd8\x13\x6d"
}
};

static const int vector_count = sizeof(tests) / sizeof(struct TEST_VECTOR);

static unsigned char scratch[1024];

static int check_test_vector(int index, struct TEST_VECTOR test)
{
    if (!prim_avail(test.primitive))
    {
        lprintf(WARN, "Algorithm %s not available - skipping.",
                      byellow(prim_name(test.primitive)));
        return 1;
    }
    else
    {
        size_t check_len = test.input_len;
        int err;

        /* Encryption is in place - copy plaintext to scratch buffer. */
        memcpy(scratch, test.input, check_len);

        /* Note there is no need to try to decrypt - stream encryption is
         * done via xor_buffer, so checking the latter function suffices. */
        err = ordo_enc_stream(test.primitive, 0,
                              test.key, test.key_len,
                              scratch, check_len);

        if (err)
        {
            /* If an error occurs, the test failed. */
            return 0;
        }

        if (memcmp(test.expected, scratch, check_len))
        {
            return 0;
        }
        else
        {
            return 1;
        }
    }
}

int test_stream(void)
{
    int t;

    for (t = 0; t < vector_count; ++t)
        if (!check_test_vector(t, tests[t])) return 0;

    return 1;
}

int test_stream_utilities(void)
{
    return 1;
}
