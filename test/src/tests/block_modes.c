#include "testenv.h"
#include <string.h>
#include "ordo.h"

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

static unsigned char scratch[1024];

static int check_test_vector(int index, struct TEST_VECTOR test)
{
    const struct BLOCK_MODE *mode = block_mode_by_name(test.name);
    if (!mode)
    {
        lprintf(WARN, "Algorithm %s not found - skipping.", byellow(test.name));
        return 1; /* If skipping, the test passed by convention. */
    }
    else
    {
        size_t check_len = test.in_len;
        int err;

        /* We will encrypt in place, for simplicity (this also implicitly
         * tests buffered encryption, by definition). Also note that the
         * NullCipher uses no key, so no need to pass that in. */
        err = ordo_enc_block(ordo_nullcipher(), 0, mode, 0,
                             1, /* encryption */
                             0, 0, /* no key */
                             test.iv, test.iv_len,
                             test.input, check_len,
                             scratch, &check_len);

        if (err)
        {
            return 0;
        }

        if (check_len != (size_t)test.out_len)
        {
            return 0;
        }

        if (memcmp(test.expected, scratch, check_len))
        {
            return 0;
        }

        /* Now we decrypt, hoping to get back the original input. */
        err = ordo_enc_block(ordo_nullcipher(), 0, mode, 0,
                             0, /* decryption */
                             0, 0, /* no key */
                             test.iv, test.iv_len,
                             scratch, check_len,
                             scratch, &check_len);

        if (err)
        {
            return 0;
        }

        if (check_len != (size_t)test.in_len)
        {
            return 0;
        }

        if (memcmp(test.input, scratch, check_len))
        {
            return 0;
        }
        else
        {
            return 1;
        }
    }
}

int test_block_modes(void)
{
    int t;

    for (t = 0; t < vector_count; ++t)
        if (!check_test_vector(t, tests[t])) return 0;

    return 1;
}

int test_block_modes_utilities(void)
{
    size_t t, count = block_mode_count();

    for (t = 0; t < count; ++t)
    {
        const struct BLOCK_MODE *mode = block_mode_by_index(t);
        if (!mode) return 0;
    }

    return 1;
}
