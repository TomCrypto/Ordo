#include "testenv.h"
#include <string.h>
#include "ordo.h"

struct TEST_VECTOR
{
    size_t input_len;
    const char *input;
    const char *expected;
};

static struct TEST_VECTOR tests[] = {
{
    0,
    "",
    "\xc8\x87\x70\x87\xda\x56\xe0\x72\x87\x0d\xaa\x84\x3f\x17\x6e\x94"
    "\x53\x11\x59\x29\x09\x4c\x3a\x40\xc4\x63\xa1\x96\xc2\x9b\xf7\xba"
},
{
    1,
    "\x00",
    "\x34\xe2\xb6\x5b\xf0\xbe\x66\x7c\xa5\xde\xba\x82\xc3\x7c\xb2\x53"
    "\xeb\x9f\x84\x74\xf3\x42\x6b\xa6\x22\xa2\x52\x19\xfd\x18\x24\x33"
},
{
    1,
    "\xff",
    "\x0b\x98\xdc\xd1\x98\xea\x0e\x50\xa7\xa2\x44\xc4\x44\xe2\x5c\x23"
    "\xda\x30\xc1\x0f\xc9\xa1\xf2\x70\xa6\x63\x7f\x1f\x34\xe6\x7e\xd2"
},
{
    4,
    "\x00\x00\x00\x00",
    "\x69\x60\x42\x6d\x85\xf4\xf1\x0d\xaa\x23\x21\x3d\xe5\xad\xd2\x10"
    "\x1f\x4c\x1b\x79\x0b\x53\x0b\xf7\xaa\x66\xf0\x93\x0b\xb6\xb9\x06"
},
{
    4,
    "\xff\xfe\xfd\xfc",
    "\xaf\xb9\x2d\x1e\x32\xfa\x99\x49\x3d\xe9\x27\x6c\x6c\xa5\x28\xcb"
    "\x6b\x33\xff\x0a\xd2\x00\xf3\x39\xc0\x78\x10\x02\xa1\x37\x34\xbf"
},
{
    8,
    "\xff\xfe\xfd\xfc\xfb\xfa\xf9\xf8",
    "\x0b\x5c\xa5\x67\x12\xac\x0d\x94\x50\xbd\x83\x98\x47\x9e\x28\x24"
    "\x6c\x32\x96\x47\x13\x8d\x2b\xdb\x45\xe1\x63\x77\x8f\x83\x08\xd4"
},
{
    32,
    "\xff\xfe\xfd\xfc\xfb\xfa\xf9\xf8\xf7\xf6\xf5\xf4\xf3\xf2\xf1\xf0"
    "\xef\xee\xed\xec\xeb\xea\xe9\xe8\xe7\xe6\xe5\xe4\xe3\xe2\xe1\xe0",
    "\x8d\x0f\xa4\xef\x77\x7f\xd7\x59\xdf\xd4\x04\x4e\x6f\x6a\x5a\xc3"
    "\xc7\x74\xae\xc9\x43\xdc\xfc\x07\x92\x7b\x72\x3b\x5d\xbf\x40\x8b"
},
{
    48,
    "\xff\xfe\xfd\xfc\xfb\xfa\xf9\xf8\xf7\xf6\xf5\xf4\xf3\xf2\xf1\xf0"
    "\xef\xee\xed\xec\xeb\xea\xe9\xe8\xe7\xe6\xe5\xe4\xe3\xe2\xe1\xe0"
    "\xdf\xde\xdd\xdc\xdb\xda\xd9\xd8\xd7\xd6\xd5\xd4\xd3\xd2\xd1\xd0",
    "\x8a\x48\x42\xd9\xc1\xe9\xf2\x4e\x38\x86\xfc\x0b\x10\x75\x55\xf9"
    "\xed\xa8\x19\x77\x07\x74\x9c\xec\xc7\x77\x24\x02\xb2\xfe\xa0\xc5"
}
};

static const int vector_count = sizeof(tests) / sizeof(struct TEST_VECTOR);

static unsigned char scratch[1024];

static int config_block(void)
{
    int t;

    /* Test the generic output block and see if we get the same output. */
    struct SKEIN256_PARAMS params = skein256_default();
    
    if (!prim_available(HASH_SKEIN256))
    {
        lprintf(WARN, "Algorithm %s not available - skipping.",
                      byellow(prim_name(HASH_SKEIN256)));
        return 1;
    }

    for (t = 0; t < vector_count; ++t)
    {
        struct TEST_VECTOR test = tests[t];
        int err;

        err = ordo_digest(HASH_SKEIN256, &params,
                          test.input, test.input_len,
                          scratch);

        if (err)
        {
            return 0;
        }

        if (memcmp(scratch, test.expected, params.out_len / 8))
        {
            return 0;
        }
    }

    return 1;
}

int test_skein256(void)
{
    return config_block();
}
