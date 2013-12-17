#include "tests/pbkdf2/pbkdf2.h"

struct TEST_VECTOR
{
    const char *name;
    size_t pwd_len;
    const char *pwd;
    size_t salt_len;
    const char *salt;
    size_t iterations;
    size_t out_len;
    const char *expected;
};

static struct TEST_VECTOR tests[] = {
{
    "SHA-256",
    8,
    "password",
    4,
    "salt",
    1,
    32,
    "\x12\x0f\xb6\xcf\xfc\xf8\xb3\x2c\x43\xe7\x22\x52\x56\xc4\xf8\x37"
    "\xa8\x65\x48\xc9\x2c\xcc\x35\x48\x08\x05\x98\x7c\xb7\x0b\xe1\x7b"
},
{
    "SHA-256",
    8,
    "password",
    4,
    "salt",
    2,
    32,
    "\xae\x4d\x0c\x95\xaf\x6b\x46\xd3\x2d\x0a\xdf\xf9\x28\xf0\x6d\xd0"
    "\x2a\x30\x3f\x8e\xf3\xc2\x51\xdf\xd6\xe2\xd8\x5a\x95\x47\x4c\x43"
},
/* Takes painfully long for little benefit - ignored. */
/*{
    "SHA-256",
    8,
    "password",
    4,
    "salt",
    16777216,
    32,
    "\xcf\x81\xc6\x6f\xe8\xcf\xc0\x4d\x1f\x31\xec\xb6\x5d\xab\x40\x89"
    "\xf7\xf1\x79\xe8\x9b\x3b\x0b\xcb\x17\xad\x10\xe3\xac\x6e\xba\x46"
},*/
{
    "SHA-256",
    9,
    "\x70\x61\x73\x73\x00\x77\x6f\x72\x64",
    5,
    "\x73\x61\x00\x6c\x74",
    4096,
    16,
    "\x89\xb6\x9d\x05\x16\xf8\x29\x89\x3c\x69\x62\x26\x65\x0a\x86\x87"
},
{
    "SHA-256",
    24,
    "passwordPASSWORDpassword",
    36,
    "saltSALTsaltSALTsaltSALTsaltSALTsalt",
    4096,
    40,
    "\x34\x8c\x89\xdb\xcb\xd3\x2b\x2f\x32\xd8\x14\xb8\x11\x6e\x84\xcf"
    "\x2b\x17\x34\x7e\xbc\x18\x00\x18\x1c\x4e\x2a\x1f\xb8\xdd\x53\xe1"
    "\xc6\x35\x51\x8c\x7d\xac\x47\xe9"
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
        size_t check_len = test.out_len;
        int err;

        err = pbkdf2(hash, 0,
                     test.pwd, test.pwd_len,
                     test.salt, test.salt_len,
                     test.iterations,
                     scratch, check_len);

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

int test_pbkdf2(char *output, size_t maxlen, FILE *ext)
{
    int t;

    if (ext) fprintf(ext, "[*] Beginning PBKDF2 test vectors.\n\n");

    for (t = 0; t < vector_count; ++t)
    {
        if (!check_test_vector(t, tests[t], ext))
        {
            snprintf(output, maxlen, "Test vector for '%s'.", tests[t].name);
            return 0;
        }
    }

    if (ext) fprintf(ext, "[*] Finished PBKDF2 test vectors.\n\n");
    pass("Generic PBKDF2 test vectors.");
}
