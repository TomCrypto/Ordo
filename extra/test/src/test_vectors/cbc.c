/*===-- test_vectors/cbc.c -------------------------------*- TEST -*- C -*-===*/
/**
*** @file
*** @brief Test Vectors
***
*** Test vectors for the CBC block mode.
**/
/*===----------------------------------------------------------------------===*/

#include "testenv.h"

/*===----------------------------------------------------------------------===*/

struct TEST_VECTOR
{
    const char *key;
    size_t key_len;
    const char *iv;
    size_t iv_len;
    const char *in;
    size_t in_len;
    const char *out;
    size_t out_len;
    prim_t cipher;
    int use_params;
    struct CBC_PARAMS params;
};

static const struct TEST_VECTOR tests[] =
{
{
    0, 0,
    "ZZZZZZZZZZZZZZZZ", 16,
    "\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb"
    "\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb"
    "\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb", 47,
    "\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1"
    "\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a"
    "\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\x5b", 48,
    BLOCK_NULLCIPHER,
    1, {
        1
    }
},
{
    "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c", 16,
    "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F", 16,
    "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a", 16,
    "\x76\x49\xab\xac\x81\x19\xb2\x46\xce\xe9\x8e\x9b\x12\xe9\x19\x7d", 16,
    BLOCK_AES,
    1, {
        0
    }
}
};

#define MAX_OUT_LEN 48

/*===----------------------------------------------------------------------===*/

static int check(const struct TEST_VECTOR *test)
{
    unsigned char out[MAX_OUT_LEN];
    struct BLOCK_MODE_STATE ctx;
    size_t total = 0, out_len;
    struct BLOCK_STATE blk;

    if (!prim_avail(test->cipher))
        return 1;

    ASSERT_SUCCESS(block_init(&blk, test->key, test->key_len,
                              test->cipher, 0));

    ASSERT_SUCCESS(block_mode_init(&ctx, &blk, test->iv, test->iv_len, 1,
                                   BLOCK_MODE_CBC, test->use_params
                                                 ? &test->params
                                                 : 0));

    block_mode_update(&ctx, &blk, test->in, test->in_len,
                      out, &out_len);
    total += out_len;

    ASSERT_SUCCESS(block_mode_final(&ctx, &blk,  out + total, &out_len));

    total += out_len;

    ASSERT_EQ(total, test->out_len);

    ASSERT_BUF_EQ(out, test->out, test->out_len);

    total = 0;

    ASSERT_SUCCESS(block_mode_init(&ctx, &blk, test->iv, test->iv_len, 0,
                                   BLOCK_MODE_CBC, test->use_params
                                                 ? &test->params
                                                 : 0));

    block_mode_update(&ctx, &blk, test->out, test->out_len,
                      out, &out_len);
    total += out_len;

    ASSERT_SUCCESS(block_mode_final(&ctx, &blk, out + total, &out_len));

    total += out_len;

    ASSERT_EQ(total, test->in_len);

    ASSERT_BUF_EQ(out, test->in, test->in_len);

    block_final(&blk);

    return 1;
}

int test_vectors_cbc(void);
int test_vectors_cbc(void)
{
    size_t t;

    if (!prim_avail(BLOCK_MODE_CBC))
        return 1;

    for (t = 0; t < ARRAY_SIZE(tests); ++t)
        if (!check(tests + t)) return 0;

    return 1;
}
