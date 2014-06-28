/*===-- test/test_vectors/ctr.c ------------------------*- PUBLIC -*- C -*-===*/
/**
*** @file
*** @brief Test Vectors
***
*** Test vectors for the CTR block mode.
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
};

static const struct TEST_VECTOR tests[] =
{
{
    0, 0,
    "ZZZZZZZZZZZZZZZZ", 16,
    "\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb"
    "\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb"
    "\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb\xbb", 48,
    "\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1"
    "\xe0\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1"
    "\xe7\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1\xe1", 48,
    BLOCK_NULLCIPHER
}
};

#define MAX_OUT_LEN 48

/*===----------------------------------------------------------------------===*/

static int check(struct TEST_VECTOR test)
{
    unsigned char out[MAX_OUT_LEN];
    struct BLOCK_MODE_STATE ctx;
    size_t total = 0, out_len;
    struct BLOCK_STATE blk;

    if (!prim_avail(test.cipher))
        return 1;

    ASSERT_SUCCESS(block_init(&blk, test.key, test.key_len, test.cipher, 0));

    ASSERT_SUCCESS(block_mode_init(&ctx, &blk, test.iv, test.iv_len, 1,
                                   BLOCK_MODE_CTR, 0));

    block_mode_update(&ctx, &blk, test.in, test.in_len,
                      out, &out_len);
    total += out_len;

    ASSERT_SUCCESS(block_mode_final(&ctx, &blk,  out + total, &out_len));

    total += out_len;

    ASSERT_EQ(total, test.out_len);

    ASSERT_BUF_EQ(out, test.out, test.out_len);

    total = 0;

    ASSERT_SUCCESS(block_mode_init(&ctx, &blk, test.iv, test.iv_len, 0,
                                   BLOCK_MODE_CTR, 0));

    block_mode_update(&ctx, &blk, test.out, test.out_len,
                      out, &out_len);
    total += out_len;

    ASSERT_SUCCESS(block_mode_final(&ctx, &blk, out + total, &out_len));

    total += out_len;

    ASSERT_EQ(total, test.in_len);

    ASSERT_BUF_EQ(out, test.in, test.in_len);

    block_final(&blk);

    return 1;
}

int test_vectors_ctr(void);
int test_vectors_ctr(void)
{
    size_t t;

    if (!prim_avail(BLOCK_MODE_CTR))
        return 1;

    for (t = 0; t < ARRAY_SIZE(tests); ++t)
        if (!check(tests[t])) return 0;

    return 1;
}
