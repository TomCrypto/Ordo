#include "tests/digest/digest.h"

struct TEST_VECTOR
{
    const char *name;
    size_t input_len;
    const char *input;
    const char *expected;
};

static struct TEST_VECTOR tests[] = {
{
    "SHA-256",
    0,
    "",
    "\xe3\xb0\xc4\x42\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99\x6f\xb9\x24"
    "\x27\xae\x41\xe4\x64\x9b\x93\x4c\xa4\x95\x99\x1b\x78\x52\xb8\x55"
},
{
    "SHA-256",
    1,
    "A",
    "\x55\x9a\xea\xd0\x82\x64\xd5\x79\x5d\x39\x09\x71\x8c\xdd\x05\xab"
    "\xd4\x95\x72\xe8\x4f\xe5\x55\x90\xee\xf3\x1a\x88\xa0\x8f\xdf\xfd"
},
{
    "SHA-256",
    5,
    "hello",
    "\x2c\xf2\x4d\xba\x5f\xb0\xa3\x0e\x26\xe8\x3b\x2a\xc5\xb9\xe2\x9e"
    "\x1b\x16\x1e\x5c\x1f\xa7\x42\x5e\x73\x04\x33\x62\x93\x8b\x98\x24"
},
{
    "SHA-256",
    14,
    "\x6d\x65\x73\x73\x61\x67\x65\x20\x64\x69\x67\x65\x73\x74",
    "\xf7\x84\x6f\x55\xcf\x23\xe1\x4e\xeb\xea\xb5\xb4\xe1\x55\x0c\xad"
    "\x5b\x50\x9e\x33\x48\xfb\xc4\xef\xa3\xa1\x41\x3d\x39\x3c\xb6\x50"
},
{
    "SHA-256",
    56,
    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
    "\x24\x8d\x6a\x61\xd2\x06\x38\xb8\xe5\xc0\x26\x93\x0c\x3e\x60\x39"
    "\xa3\x3c\xe4\x59\x64\xff\x21\x67\xf6\xec\xed\xd4\x19\xdb\x06\xc1"
},
{
    "SHA-256",
    63,
    "\x46\x6f\x72\x20\x74\x68\x69\x73\x20\x73\x61\x6d\x70\x6c\x65\x2c"
    "\x20\x74\x68\x69\x73\x20\x36\x33\x2d\x62\x79\x74\x65\x20\x73\x74"
    "\x72\x69\x6e\x67\x20\x77\x69\x6c\x6c\x20\x62\x65\x20\x75\x73\x65"
    "\x64\x20\x61\x73\x20\x69\x6e\x70\x75\x74\x20\x64\x61\x74\x61",
    "\xf0\x8a\x78\xcb\xba\xee\x08\x2b\x05\x2a\xe0\x70\x8f\x32\xfa\x1e"
    "\x50\xc5\xc4\x21\xaa\x77\x2b\xa5\xdb\xb4\x06\xa2\xea\x6b\xe3\x42"
},
{
    "SHA-256",
    64,
    "\x54\x68\x69\x73\x20\x69\x73\x20\x65\x78\x61\x63\x74\x6c\x79\x20"
    "\x36\x34\x20\x62\x79\x74\x65\x73\x20\x6c\x6f\x6e\x67\x2c\x20\x6e"
    "\x6f\x74\x20\x63\x6f\x75\x6e\x74\x69\x6e\x67\x20\x74\x68\x65\x20"
    "\x74\x65\x72\x6d\x69\x6e\x61\x74\x69\x6e\x67\x20\x62\x79\x74\x65",
    "\xab\x64\xef\xf7\xe8\x8e\x2e\x46\x16\x5e\x29\xf2\xbc\xe4\x18\x26"
    "\xbd\x4c\x7b\x35\x52\xf6\xb3\x82\xa9\xe7\xd3\xaf\x47\xc2\x45\xf8"
},
{
    "MD5",
    0,
    "",
    "\xd4\x1d\x8c\xd9\x8f\x00\xb2\x04\xe9\x80\x09\x98\xec\xf8\x42\x7e"
},
{
    "MD5",
    1,
    "a",
    "\x0c\xc1\x75\xb9\xc0\xf1\xb6\xa8\x31\xc3\x99\xe2\x69\x77\x26\x61"
},
{
    "MD5",
    3,
    "abc",
    "\x90\x01\x50\x98\x3c\xd2\x4f\xb0\xd6\x96\x3f\x7d\x28\xe1\x7f\x72"
},
{
    "MD5",
    14,
    "\x6d\x65\x73\x73\x61\x67\x65\x20\x64\x69\x67\x65\x73\x74",
    "\xf9\x6b\x69\x7d\x7c\xb7\x93\x8d\x52\x5a\x2f\x31\xaa\xf1\x61\xd0"
},
{
    "MD5",
    26,
    "abcdefghijklmnopqrstuvwxyz",
    "\xc3\xfc\xd3\xd7\x61\x92\xe4\x00\x7d\xfb\x49\x6c\xca\x67\xe1\x3b"
},
{
    "MD5",
    62,
    "\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
    "\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x61\x62\x63\x64\x65\x66"
    "\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76"
    "\x77\x78\x79\x7a\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39",
    "\xd1\x74\xab\x98\xd2\x77\xd9\xf5\xa5\x61\x1c\x2c\x9f\x41\x9d\x9f"
},
{
    "MD5",
    80,
    "\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31\x32\x33\x34\x35\x36"
    "\x37\x38\x39\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31\x32"
    "\x33\x34\x35\x36\x37\x38\x39\x30\x31\x32\x33\x34\x35\x36\x37\x38"
    "\x39\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31\x32\x33\x34"
    "\x35\x36\x37\x38\x39\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30",
    "\x57\xed\xf4\xa2\x2b\xe3\xc9\x55\xac\x49\xda\x2e\x21\x07\xb6\x7a"
},
{
    "Skein-256",
    0,
    "",
    "\xc8\x87\x70\x87\xda\x56\xe0\x72\x87\x0d\xaa\x84\x3f\x17\x6e\x94"
    "\x53\x11\x59\x29\x09\x4c\x3a\x40\xc4\x63\xa1\x96\xc2\x9b\xf7\xba"
},
{
    "Skein-256",
    1,
    "\x00",
    "\x34\xe2\xb6\x5b\xf0\xbe\x66\x7c\xa5\xde\xba\x82\xc3\x7c\xb2\x53"
    "\xeb\x9f\x84\x74\xf3\x42\x6b\xa6\x22\xa2\x52\x19\xfd\x18\x24\x33"
},
{
    "Skein-256",
    1,
    "\xff",
    "\x0b\x98\xdc\xd1\x98\xea\x0e\x50\xa7\xa2\x44\xc4\x44\xe2\x5c\x23"
    "\xda\x30\xc1\x0f\xc9\xa1\xf2\x70\xa6\x63\x7f\x1f\x34\xe6\x7e\xd2"
},
{
    "Skein-256",
    4,
    "\x00\x00\x00\x00",
    "\x69\x60\x42\x6d\x85\xf4\xf1\x0d\xaa\x23\x21\x3d\xe5\xad\xd2\x10"
    "\x1f\x4c\x1b\x79\x0b\x53\x0b\xf7\xaa\x66\xf0\x93\x0b\xb6\xb9\x06"
},
{
    "Skein-256",
    4,
    "\xff\xfe\xfd\xfc",
    "\xaf\xb9\x2d\x1e\x32\xfa\x99\x49\x3d\xe9\x27\x6c\x6c\xa5\x28\xcb"
    "\x6b\x33\xff\x0a\xd2\x00\xf3\x39\xc0\x78\x10\x02\xa1\x37\x34\xbf"
},
{
    "Skein-256",
    8,
    "\xff\xfe\xfd\xfc\xfb\xfa\xf9\xf8",
    "\x0b\x5c\xa5\x67\x12\xac\x0d\x94\x50\xbd\x83\x98\x47\x9e\x28\x24"
    "\x6c\x32\x96\x47\x13\x8d\x2b\xdb\x45\xe1\x63\x77\x8f\x83\x08\xd4"
},
{
    "Skein-256",
    32,
    "\xff\xfe\xfd\xfc\xfb\xfa\xf9\xf8\xf7\xf6\xf5\xf4\xf3\xf2\xf1\xf0"
    "\xef\xee\xed\xec\xeb\xea\xe9\xe8\xe7\xe6\xe5\xe4\xe3\xe2\xe1\xe0",
    "\x8d\x0f\xa4\xef\x77\x7f\xd7\x59\xdf\xd4\x04\x4e\x6f\x6a\x5a\xc3"
    "\xc7\x74\xae\xc9\x43\xdc\xfc\x07\x92\x7b\x72\x3b\x5d\xbf\x40\x8b"
},
{
    "Skein-256",
    48,
    "\xff\xfe\xfd\xfc\xfb\xfa\xf9\xf8\xf7\xf6\xf5\xf4\xf3\xf2\xf1\xf0"
    "\xef\xee\xed\xec\xeb\xea\xe9\xe8\xe7\xe6\xe5\xe4\xe3\xe2\xe1\xe0"
    "\xdf\xde\xdd\xdc\xdb\xda\xd9\xd8\xd7\xd6\xd5\xd4\xd3\xd2\xd1\xd0",
    "\x8a\x48\x42\xd9\xc1\xe9\xf2\x4e\x38\x86\xfc\x0b\x10\x75\x55\xf9"
    "\xed\xa8\x19\x77\x07\x74\x9c\xec\xc7\x77\x24\x02\xb2\xfe\xa0\xc5"
}
};

static const int vector_count = sizeof(tests) / sizeof(struct TEST_VECTOR);

static int check_test_vector(int index, struct TEST_VECTOR test, FILE *ext)
{
    const struct HASH_FUNCTION *hash = hash_function_by_name(test.name);
    if (ext) fprintf(ext, "[*] Test vector #%d '%s'.\n", index, test.name);
    if (!hash)
    {
        if (ext) fprintf(ext, "[+] Algorithm not found - skipping.\n\n");
        return 1; /* If skipping, the test passed by convention. */
    }
    else
    {
        size_t check_len = digest_length(hash);
        int err;

        err = ordo_digest(hash, 0,
                          test.input, test.input_len,
                          scratch);

        if (err)
        {
            /* If an error occurs, the test failed. */
            if (ext) fprintf(ext, "[!] FAILED - %s.\n\n",
                             ordo_error_msg(err));
            return 0;
        }

        if (memcmp(test.expected, scratch, check_len))
        {
            if (ext)
            {
                fprintf(ext, "[!] FAILED, computed ");
                hex(ext, scratch, check_len);
                fprintf(ext, " (differs from expected output).\n");
                fprintf(ext, "[!] Test suite failed, aborting.\n\n");
            }

            return 0;
        }
        else
        {
            if (ext) fprintf(ext, "[+] PASSED!\n\n");
            return 1;
        }
    }
}

int test_digest(char *output, size_t maxlen, FILE *ext)
{
    int t;

    if (ext) fprintf(ext, "[*] Beginning hash function test vectors.\n\n");

    for (t = 0; t < vector_count; ++t)
    {
        if (!check_test_vector(t, tests[t], ext))
        {
            snprintf(output, maxlen, "Test vector for '%s'.", tests[t].name);
            return 0;
        }
    }

    if (ext) fprintf(ext, "[*] Finished hash function test vectors.\n\n");
    pass("Generic hash function test vectors.");
}

int test_digest_utilities(char *output, size_t maxlen, FILE *ext)
{
    size_t t, count = hash_function_count();

    if (ext) fprintf(ext, "[*] Detected %d hash functions.\n", (int)count);

    for (t = 0; t < count; ++t)
    {
        const struct HASH_FUNCTION *hash = hash_function_by_index(t);
        if (!hash)
        {
            if (ext) fprintf(ext, "[!] Index %d rejected!\n\n", (int)t);
            fail("Supposedly valid hash function index is invalid.");
        }
    }

    if (ext) fprintf(ext, "[+] All hash function indices are valid.\n\n");
    pass("Hash function library utilities.");
}
