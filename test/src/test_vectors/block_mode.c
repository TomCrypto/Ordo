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

struct TEST_VECTOR
{
    prim_t primitive;
    prim_t cipher;
    size_t key_len;
    const char *key;
    size_t iv_len;
    const char *iv;
    size_t in_len;
    const char *input;
    size_t out_len;
    const char *expected;
    int padding;
};

static const struct TEST_VECTOR tests[] =
{
    {
        BLOCK_MODE_ECB,
        BLOCK_NULLCIPHER,
        0,
        0,
        0,
        "",
        11,
        "\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45",
        16,
        "\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x05\x05\x05\x05\x05",
        1
    },
    {
        BLOCK_MODE_CBC,
        BLOCK_NULLCIPHER,
        0,
        0,
        16,
        "ZZZZZZZZZZZZZZZZ",
        47,
        "\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb"
        "\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb"
        "\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb",
        48,
        "\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1"
        "\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a"
        "\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\x5b",
        1
    },
    {
        BLOCK_MODE_OFB,
        BLOCK_NULLCIPHER,
        0,
        0,
        16,
        "ZZZZZZZZZZZZZZZZ",
        48,
        "\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb"
        "\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb"
        "\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb",
        48,
        "\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1"
        "\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1"
        "\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1",
        0
    },
    {
        BLOCK_MODE_CTR,
        BLOCK_NULLCIPHER,
        0,
        0,
        16,
        "ZZZZZZZZZZZZZZZZ",
        48,
        "\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb"
        "\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb"
        "\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb",
        48,
        "\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1"
        "\xe0\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1"
        "\xe7\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1",
        0
    },
    {
        BLOCK_MODE_CFB,
        BLOCK_NULLCIPHER,
        0,
        0,
        16,
        "ZZZZZZZZZZZZZZZZ",
        48,
        "\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb"
        "\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb"
        "\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb",
        48,
        "\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1"
        "\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a"
        "\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1",
        0
    },
    {
        BLOCK_MODE_CBC,
        BLOCK_AES,
        16,
        "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
        16,
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F",
        16,
        "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a",
        16,
        "\x76\x49\xab\xac\x81\x19\xb2\x46\xce\xe9\x8e\x9b\x12\xe9\x19\x7d",
        0
    }
};

/*===----------------------------------------------------------------------===*/

static int check(struct TEST_VECTOR test)
{
    unsigned char scratch[1024];
    struct BLOCK_MODE_STATE ctx;
    struct BLOCK_STATE blk;
    size_t total = 0, out;

    if (!prim_avail(test.cipher))
        return 1;
    if (!prim_avail(test.primitive))
        return 1;

    ASSERT_SUCCESS(block_init(&blk, test.key, test.key_len, test.cipher, 0));

    if (test.primitive == BLOCK_MODE_ECB)
    {
        struct ECB_PARAMS params = {0};
        params.padding = test.padding;

        ASSERT_SUCCESS(block_mode_init(&ctx, &blk, test.iv, test.iv_len,
                                       1, test.primitive, &params));
    }
    else if (test.primitive == BLOCK_MODE_CBC)
    {
        struct CBC_PARAMS params = {0};
        params.padding = test.padding;

        ASSERT_SUCCESS(block_mode_init(&ctx, &blk, test.iv, test.iv_len,
                                       1, test.primitive, &params));
    }
    else
    {
        ASSERT_SUCCESS(block_mode_init(&ctx, &blk, test.iv, test.iv_len,
                                       1, test.primitive, 0));
    }

    block_mode_update(&ctx, &blk, test.input, test.in_len,
                      scratch, &out);
    total += out;

    ASSERT_SUCCESS(block_mode_final(&ctx, &blk,  scratch + total, &out));

    total += out;

    ASSERT_EQ(total, test.out_len);

    ASSERT_BUF_EQ(scratch, test.expected, test.out_len);

    total = 0;

    if (test.primitive == BLOCK_MODE_ECB)
    {
        struct ECB_PARAMS params = {0};
        params.padding = test.padding;

        ASSERT_SUCCESS(block_mode_init(&ctx, &blk, test.iv, test.iv_len,
                                       0, test.primitive, &params));
    }
    else if (test.primitive == BLOCK_MODE_CBC)
    {
        struct CBC_PARAMS params = {0};
        params.padding = test.padding;

        ASSERT_SUCCESS(block_mode_init(&ctx, &blk, test.iv, test.iv_len,
                                       0, test.primitive, &params));
    }
    else
    {
        ASSERT_SUCCESS(block_mode_init(&ctx, &blk, test.iv, test.iv_len,
                                       0, test.primitive, 0));
    }

    block_mode_update(&ctx, &blk, test.expected, test.out_len,
                      scratch, &out);
    total += out;

    ASSERT_SUCCESS(block_mode_final(&ctx, &blk, scratch + total, &out));

    total += out;

    ASSERT_EQ(total, test.in_len);

    ASSERT_BUF_EQ(scratch, test.input, test.in_len);

    block_final(&blk);

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
