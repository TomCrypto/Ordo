#include <tests/block_modes/block_modes.h>

#include <enc/enc_block.h>

/* Note the block mode tests are always run against the NullCipher.
 * This is to ensure the underlying block cipher cannot be responsible
 * for the failure of a given block mode test vector. */
struct TEST_VECTOR
{
    const char *name;
    size_t iv_len;
    const char *iv;
    size_t in_len;
    const char *input;
    size_t out_len;
    const char *expected;
};

static struct TEST_VECTOR tests[] = {
{
    "ECB",
    0,
    "",
    11,
    "\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45",
    16,
    "\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x05\x05\x05\x05\x05"
},
{
    "CBC",
    16,
    "ZZZZZZZZZZZZZZZZ",
    47,
    "\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb"
    "\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb"
    "\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb",
    48,
    "\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1"
    "\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a"
    "\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\x5b"
},
{
    "OFB",
    16,
    "ZZZZZZZZZZZZZZZZ",
    48,
    "\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb"
    "\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb"
    "\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb",
    48,
    "\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1"
    "\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1"
    "\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1"
},
{
    "CTR",
    16,
    "ZZZZZZZZZZZZZZZZ",
    48,
    "\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb"
    "\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb"
    "\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb",
    48,
    "\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1"
    "\xe0\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1"
    "\xe7\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1"
},
{
    "CFB",
    16,
    "ZZZZZZZZZZZZZZZZ",
    48,
    "\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb"
    "\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb"
    "\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb",
    48,
    "\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1"
    "\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a"
    "\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1"
}
};

static const int vector_count = sizeof(tests) / sizeof(struct TEST_VECTOR);

static int check_test_vector(int index, struct TEST_VECTOR test, FILE *ext)
{
    const struct BLOCK_MODE *mode = block_mode_by_name(test.name);
    if (ext) fprintf(ext, "[*] Test vector #%d '%s'.\n", index, test.name);
    if (!mode)
    {
        if (ext) fprintf(ext, "[+] Algorithm not found - skipping.\n\n");
        return 1; /* If skipping, the test passed by convention. */
    }
    else
    {
        size_t check_len = test.in_len;
        int err;

        /* We will encrypt in place, for simplicity (this also implicitly
         * tests buffered encryption, by definition). Also note that the
         * NullCipher uses no key, so no need to pass that in. */
        err = ordo_enc_block(NullCipher(), 0, mode, 0,
                             1, /* encryption */
                             0, 0, /* no key */
                             test.iv, test.iv_len,
                             test.input, check_len,
                             scratch, &check_len);

        if (err)
        {
            /* If an error occurs, the test failed. */
            if (ext) fprintf(ext, "[!] FAILED - %s.\n\n", error_msg(err));
            return 0;
        }

        if (check_len != (size_t)test.out_len)
        {
            if (ext)
            {
                fprintf(ext, "[!] FAILED, expected %d bytes",
                        (int)test.out_len);
                fprintf(ext, ", got %d bytes.\n", (int)check_len);
                fprintf(ext, "[!] Test suite failed, aborting.\n\n");
            }

            return 0;
        }

        if (memcmp(test.expected, scratch, check_len))
        {
            if (ext)
            {
                fprintf(ext, "[!] FAILED - [encryption] computed ");
                hex(ext, scratch, check_len);
                fprintf(ext, " (differs from expected output).\n");
                fprintf(ext, "[!] Test suite failed, aborting.\n\n");
            }

            return 0;
        }

        /* Now we decrypt, hoping to get back the original input. */
        err = ordo_enc_block(NullCipher(), 0, mode, 0,
                             0, /* decryption */
                             0, 0, /* no key */
                             test.iv, test.iv_len,
                             scratch, check_len,
                             scratch, &check_len);

        if (err)
        {
            /* If an error occurs, the test failed. */
            if (ext) fprintf(ext, "[!] FAILED - %s.\n\n", error_msg(err));
            return 0;
        }

        if (check_len != (size_t)test.in_len)
        {
            if (ext)
            {
                fprintf(ext, "[!] FAILED, expected %d bytes",
                        (int)test.in_len);
                fprintf(ext, ", got %d bytes.\n", (int)check_len);
                fprintf(ext, "[!] Test suite failed, aborting.\n\n");
            }

            return 0;
        }

        if (memcmp(test.input, scratch, check_len))
        {
            if (ext)
            {
                fprintf(ext, "[!] FAILED - [decryption] computed ");
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

int test_block_modes(char *output, size_t maxlen, FILE *ext)
{
    int t;

    if (ext) fprintf(ext, "[*] Beginning block mode test vectors.\n\n");

    for (t = 0; t < vector_count; ++t)
    {
        if (!check_test_vector(t, tests[t], ext))
        {
            snprintf(output, maxlen, "Test vector for '%s'.", tests[t].name);
            return 0;
        }
    }

    if (ext) fprintf(ext, "[*] Finished block mode test vectors.\n\n");
    pass("Generic block mode test vectors.");
}

int test_block_modes_utilities(char *output, size_t maxlen, FILE *ext)
{
    size_t t, count = block_mode_count();

    if (ext) fprintf(ext, "[*] Detected %d block modes.\n", (int)count);

    for (t = 0; t < count; ++t)
    {
        const struct BLOCK_MODE *mode = block_mode_by_id(t);
        if (!mode)
        {
            if (ext) fprintf(ext, "[!] Library rejected ID %d!\n\n", (int)t);
            fail("Supposedly valid block mode ID is invalid.");
        }
    }

    if (ext) fprintf(ext, "[+] All block mode ID's reported valid.\n\n");
    pass("Block mode library utilities.");
}
