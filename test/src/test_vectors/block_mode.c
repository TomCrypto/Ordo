/*===-- test/test_vectors/block_mode.c -----------------*- PUBLIC -*- C -*-===*/
/**
*** @file
*** @brief Test Vectors
***
*** This unit provides test vectors for the block modes.
**/
/*===----------------------------------------------------------------------===*/

#include "testenv.h"

/*===----------------------------------------------------------------------===*/

/* Note the block mode tests are always run against the NullCipher.
 * This is to ensure the underlying block cipher cannot be responsible
 * for the failure of a given block mode test vector. */
struct TEST_VECTOR
{
    prim_t primitive;
    size_t iv_len;
    const char *iv;
    size_t in_len;
    const char *input;
    size_t out_len;
    const char *expected;
};

static const struct TEST_VECTOR tests[] =
{
    {
        BLOCK_MODE_ECB,
        0,
        "",
        11,
        "\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45",
        16,
        "\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x05\x05\x05\x05\x05"
    },
    {
        BLOCK_MODE_CBC,
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
        BLOCK_MODE_OFB,
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
        BLOCK_MODE_CTR,
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
        BLOCK_MODE_CFB,
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

/*===----------------------------------------------------------------------===*/

static int check(struct TEST_VECTOR test)
{
    unsigned char scratch[1024];
    struct BLOCK_MODE_STATE ctx;
    struct BLOCK_STATE null;
    size_t total = 0, out;

    if (!prim_avail(test.primitive))
        return 1;

    ASSERT_SUCCESS(block_init(&null, 0, 0, BLOCK_NULLCIPHER, 0));

    ASSERT_SUCCESS(block_mode_init(&ctx, &null, test.iv, test.iv_len,
                                   1, test.primitive, 0));

    block_mode_update(&ctx, &null, test.input, test.in_len,
                      scratch, &out);
    total += out;

    ASSERT_SUCCESS(block_mode_final(&ctx, &null,  scratch + total, &out));

    total += out;

    ASSERT_EQ(total, test.out_len);

    ASSERT_BUF_EQ(scratch, test.expected, test.out_len);

    total = 0;

    ASSERT_SUCCESS(block_mode_init(&ctx, &null, test.iv, test.iv_len,
                                   0, test.primitive, 0));

    block_mode_update(&ctx, &null, test.expected, test.out_len,
                      scratch, &out);
    total += out;

    ASSERT_SUCCESS(block_mode_final(&ctx, &null, scratch + total, &out));

    total += out;

    ASSERT_EQ(total, test.in_len);

    ASSERT_BUF_EQ(scratch, test.input, test.in_len);

    block_final(&null);

    return 1;
}

static int check_generic(prim_t primitive)
{
    size_t t;

    for (t = 0; t < ARRAY_SIZE(tests); ++t)
        if (tests[t].primitive == primitive)
            if (!check(tests[t])) return 0;

    return 1;
}

int test_vectors_ecb(void);
int test_vectors_ecb(void)
{
    return check_generic(BLOCK_MODE_ECB);
}

int test_vectors_cbc(void);
int test_vectors_cbc(void)
{
    return check_generic(BLOCK_MODE_CBC);
}

int test_vectors_ctr(void);
int test_vectors_ctr(void)
{
    return check_generic(BLOCK_MODE_CTR);
}

int test_vectors_cfb(void);
int test_vectors_cfb(void)
{
    return check_generic(BLOCK_MODE_CFB);
}

int test_vectors_ofb(void);
int test_vectors_ofb(void)
{
    return check_generic(BLOCK_MODE_OFB);
}
