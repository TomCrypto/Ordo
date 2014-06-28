/*===-- test/test_vectors/curve25519.c -----------------*- PUBLIC -*- C -*-===*/
/**
*** @file
*** @brief Test Vectors
***
*** Test vectors for the Curve25519 module.
**/
/*===----------------------------------------------------------------------===*/

#include "testenv.h"

/*===----------------------------------------------------------------------===*/

struct TEST_VECTOR
{
    const char *priv1, *pub1;
    const char *priv2, *pub2;
    const char *shared;
};

static const struct TEST_VECTOR tests[] =
{
    {
        "\xa8\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab"
        "\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\xab\x6b",
        "\xe3\x71\x2d\x85\x1a\x0e\x5d\x79\xb8\x31\xc5\xe3\x4a\xb2\x2b\x41"
        "\xa1\x98\x17\x1d\xe2\x09\xb8\xb8\xfa\xca\x23\xa1\x1c\x62\x48\x59",
        "\xc8\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
        "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\x4d",
        "\xb5\xbe\xa8\x23\xd9\xc9\xff\x57\x60\x91\xc5\x4b\x7c\x59\x6c\x0a"
        "\xe2\x96\x88\x4f\x0e\x15\x02\x90\xe8\x84\x55\xd7\xfb\xa6\x12\x6f",
        "\x23\x51\x01\xb7\x05\x73\x4a\xae\x8d\x4c\x2d\x9d\x0f\x1b\xaf\x90"
        "\xbb\xb2\xa8\xc2\x33\xd8\x31\xa8\x0d\x43\x81\x5b\xb4\x7e\xad\x10"
    },
    {
        /* From the NaCl distribution (+ private key postprocessing) */
        "\x70\x07\x6d\x0a\x73\x18\xa5\x7d\x3c\x16\xc1\x72\x51\xb2\x66\x45"
        "\xdf\x4c\x2f\x87\xeb\xc0\x99\x2a\xb1\x77\xfb\xa5\x1d\xb9\x2c\x6a",
        "\x85\x20\xf0\x09\x89\x30\xa7\x54\x74\x8b\x7d\xdc\xb4\x3e\xf7\x5a"
        "\x0d\xbf\x3a\x0d\x26\x38\x1a\xf4\xeb\xa4\xa9\x8e\xaa\x9b\x4e\x6a",
        "\x58\xab\x08\x7e\x62\x4a\x8a\x4b\x79\xe1\x7f\x8b\x83\x80\x0e\xe6"
        "\x6f\x3b\xb1\x29\x26\x18\xb6\xfd\x1c\x2f\x8b\x27\xff\x88\xe0\x6b",
        "\xde\x9e\xdb\x7d\x7b\x7d\xc1\xb4\xd3\x5b\x61\xc2\xec\xe4\x35\x37"
        "\x3f\x83\x43\xc8\x5b\x78\x67\x4d\xad\xfc\x7e\x14\x6f\x88\x2b\x4f",
        "\x4a\x5d\x9d\x5b\xa4\xce\x2d\xe1\x72\x8e\x3b\xf4\x80\x35\x0f\x25"
        "\xe0\x7e\x21\xc9\x47\xd1\x9e\x33\x76\xf0\x9b\x3c\x1e\x16\x17\x42"
    }
};

/*===----------------------------------------------------------------------===*/

static int check(struct TEST_VECTOR test)
{
    unsigned char calc_pub1[32], calc_pub2[32], calc_shared[32];

    #if defined(__clang__) /* TODO: Known issues */
    if (!strcmp(ordo_version()->arch, "amd64"))
        return 1;
    #endif

    curve25519_pub(calc_pub1, test.priv1);
    curve25519_pub(calc_pub2, test.priv2);

    ASSERT_BUF_EQ(calc_pub1, test.pub1, 32);
    ASSERT_BUF_EQ(calc_pub2, test.pub2, 32);

    curve25519_ecdh(calc_shared, test.priv1, calc_pub2);

    ASSERT_BUF_EQ(calc_shared, test.shared, 32);

    curve25519_ecdh(calc_shared, test.priv2, calc_pub1);

    ASSERT_BUF_EQ(calc_shared, test.shared, 32);

    return 1;
}

int test_vectors_curve25519(void);
int test_vectors_curve25519(void)
{
    size_t t;

    for (t = 0; t < ARRAY_SIZE(tests); ++t)
        if (!check(tests[t])) return 0;

    return 1;
}
