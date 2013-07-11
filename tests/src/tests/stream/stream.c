#include <tests/stream/stream.h>

struct TEST_VECTOR
{
    const char *name;
    int key_len;
    const char *key;
    int input_len;
    const char *input;
    const char *expected;
};

static struct TEST_VECTOR tests[] = {
{
    "RC4",
    5,
    "\x01\x02\x03\x04\x05",
    8,
    "\x01\x23\x45\x67\x89\xab\xcd\xef",
    "\xcd\x7b\x6a\xec\x20\x59\xa8\x0d"
},
{
    "RC4",
    16,
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    16,
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    "\xc3\x4b\x11\x6d\xa0\x18\xda\x7e\x4e\x07\x96\x53\x42\xbe\xcd\x64"
},
{
    "RC4",
    16,
    "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
    16,
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    "\x12\x84\xaa\x5c\xc4\xc6\x41\x9d\xf0\x3d\xae\xb9\xdd\xc6\xb4\x38"
},
{
    "RC4",
    16,
    "\x81\x94\xfe\x03\xff\x94\xe3\x81\xd0\xcc\x91\xb0\xaa\x9d\xe8\xf0",
    16,
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    "\xf4\xf6\x95\x08\x15\x32\xea\xd3\x40\x1f\xc5\x5a\x80\x99\xe0\x1d"
},
{
    "RC4",
    16,
    "\xff\x55\xff\x55\xff\x55\xff\x55\xff\x55\xff\x55\xff\x55\xff\x55",
    16,
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    "\xd1\x30\x52\xac\x16\x78\x92\x32\x9a\x32\x14\xf7\xc3\xaa\x7f\x09"
},
{
    "RC4",
    16,
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    16,
    "\x68\x65\x6c\x6c\x6f\x20\x64\x65\x61\x72\x20\x77\x6f\x72\x6c\x64",
    "\xab\x2e\x7d\x01\xcf\x38\xbe\x1b\x2f\x75\xb6\x24\x2d\xcc\xa1\x00"
},
{
    "RC4",
    16,
    "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
    16,
    "\x68\x65\x6c\x6c\x6f\x20\x64\x65\x61\x72\x20\x77\x6f\x72\x6c\x64",
    "\x7a\xe1\xc6\x30\xab\xe6\x25\xf8\x91\x4f\x8e\xce\xb2\xb4\xd8\x5c"
},
{
    "RC4",
    16,
    "\x81\x94\xfe\x03\xff\x94\xe3\x81\xd0\xcc\x91\xb0\xaa\x9d\xe8\xf0",
    16,
    "\x68\x65\x6c\x6c\x6f\x20\x64\x65\x61\x72\x20\x77\x6f\x72\x6c\x64",
    "\x9c\x93\xf9\x64\x7a\x12\x8e\xb6\x21\x6d\xe5\x2d\xef\xeb\x8c\x79"
},
{
    "RC4",
    16,
    "\xff\x55\xff\x55\xff\x55\xff\x55\xff\x55\xff\x55\xff\x55\xff\x55",
    16,
    "\x68\x65\x6c\x6c\x6f\x20\x64\x65\x61\x72\x20\x77\x6f\x72\x6c\x64",
    "\xb9\x55\x3e\xc0\x79\x58\xf6\x57\xfb\x40\x34\x80\xac\xd8\x13\x6d"
}
};

static const int vector_count = sizeof(tests) / sizeof(struct TEST_VECTOR);

static int check_test_vector(int index, struct TEST_VECTOR test, FILE *ext)
{
    const struct STREAM_CIPHER *cipher = stream_cipher_by_name(test.name);
    if (ext) fprintf(ext, "[*] Test vector #%d '%s'.\n", index, test.name);
    if (!cipher)
    {
        if (ext) fprintf(ext, "[+] Algorithm not found - skipping.\n\n");
        return 1; /* If skipping, the test passed by convention. */
    }
    else
    {
        size_t check_len = test.input_len;
        int err;

        /* Encryption is in place - copy plaintext to scratch buffer. */
        memcpy(scratch, test.input, check_len);

        /* Note there is no need to try to decrypt - stream encryption is
         * done via xor_buffer, so checking the latter function suffices. */
        err = ordo_enc_stream(cipher, 0,
                              test.key, test.key_len,
                              scratch, check_len);

        if (err)
        {
            /* If an error occurs, the test failed. */
            if (ext) fprintf(ext, "[!] FAILED - %s.\n\n", error_msg(err));
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

int test_stream(char *output, int maxlen, FILE *ext)
{
    int t;

    if (ext) fprintf(ext, "[*] Beginning stream cipher test vectors.\n\n");

    for (t = 0; t < vector_count; ++t)
    {
        if (!check_test_vector(t, tests[t], ext))
        {
            snprintf(output, maxlen, "Test vector for '%s'.", tests[t].name);
            return 0;
        }
    }

    if (ext) fprintf(ext, "[*] Finished stream cipher test vectors.\n\n");
    pass("Generic stream cipher test vectors.");
}

int test_stream_utilities(char *output, int maxlen, FILE *ext)
{
    int t, count = STREAM_COUNT;

    if (ext) fprintf(ext, "[*] Detected %d stream ciphers.\n", count);

    for (t = 0; t < count; ++t)
    {
        const struct STREAM_CIPHER *cipher = stream_cipher_by_id(t);
        if (!cipher)
        {
            if (ext) fprintf(ext, "[!] Library rejected ID %d!\n\n", t);
            fail("Supposedly valid stream cipher ID is invalid.");
        }
    }

    if (ext) fprintf(ext, "[+] All stream cipher ID's reported valid.\n\n");
    pass("Stream cipher library utilities.");
}
