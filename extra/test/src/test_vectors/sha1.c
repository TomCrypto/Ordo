/*===-- test_vectors/sha1.c ------------------------------*- TEST -*- C -*-===*/
/**
*** @file
*** @brief Test Vectors
***
*** Test vectors for the SHA-1 hash function.
**/
/*===----------------------------------------------------------------------===*/

#include "testenv.h"

/*===----------------------------------------------------------------------===*/

struct TEST_VECTOR
{
    const char *in;
    size_t in_len;
    const char *out;
    size_t out_len;
};

static const struct TEST_VECTOR tests[] =
{
{
    "", 0,
    "\xda\x39\xa3\xee\x5e\x6b\x4b\x0d\x32\x55\xbf\xef\x95\x60\x18\x90"
    "\xaf\xd8\x07\x09", 20
},
{
    "abc", 3,
    "\xa9\x99\x3e\x36\x47\x06\x81\x6a\xba\x3e\x25\x71\x78\x50\xc2\x6c"
    "\x9c\xd0\xd8\x9d", 20
},
{
    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
    "\x84\x98\x3e\x44\x1c\x3b\xd2\x6e\xba\xae\x4a\xa1\xf9\x51\x29\xe5"
    "\xe5\x46\x70\xf1", 20
},
{
    "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
    "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", 112,
    "\xa4\x9b\x24\x46\xa0\x2c\x64\x5b\xf4\x19\xf9\x95\xb6\x70\x91\x25"
    "\x3a\x04\xa2\x59", 20
},
};

#define MAX_OUT_LEN 20

/*===----------------------------------------------------------------------===*/

static int check(const struct TEST_VECTOR *test)
{
    unsigned char out[MAX_OUT_LEN];
    struct HASH_STATE state;

    ASSERT_SUCCESS(hash_init(&state, HASH_SHA1, 0));

    hash_update(&state, test->in, test->in_len);

    hash_final(&state, out);

    ASSERT_BUF_EQ(out, test->out, test->out_len);

    return 1;
}

int test_vectors_sha1(void);
int test_vectors_sha1(void)
{
    size_t t;

    if (!prim_avail(HASH_SHA1))
        return 1;

    for (t = 0; t < ARRAY_SIZE(tests); ++t)
        if (!check(tests + t)) return 0;

    return 1;
}
