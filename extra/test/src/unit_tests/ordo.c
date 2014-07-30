/*===-- unit_tests/ordo.c --------------------------------*- TEST -*- C -*-===*/
/**
*** @file
*** @brief Test Vectors
***
*** Unit tests for the Ordo high level API.
**/
/*===----------------------------------------------------------------------===*/

#include "testenv.h"

/*===----------------------------------------------------------------------===*/

int test_ordo_digest(void);
int test_ordo_digest(void)
{
    const char *msg = "Hello, world!";
    unsigned char out[HASH_DIGEST_LEN];
    unsigned char expected[HASH_DIGEST_LEN];
    prim_t hash = prim_default(PRIM_TYPE_HASH);

    {
        struct DIGEST_CTX ctx;

        ASSERT_SUCCESS(digest_init(&ctx, hash, 0));
        digest_update(&ctx, msg, strlen(msg));
        digest_final(&ctx, expected);
    }

    ASSERT_FAILURE(ordo_digest(BLOCK_AES, 0, msg, strlen(msg), out));
    ASSERT_SUCCESS(ordo_digest(hash, 0, msg, strlen(msg), out));
    ASSERT_BUF_EQ(out, expected, digest_length(hash));

    return 1;
}

int test_ordo_hmac(void);
int test_ordo_hmac(void)
{
    const char *msg = "Hello, world!";
    const char *key = "* secret key *";
    unsigned char out[HASH_DIGEST_LEN];
    unsigned char expected[HASH_DIGEST_LEN];
    prim_t hash = prim_default(PRIM_TYPE_HASH);

    {
        struct HMAC_CTX ctx;

        ASSERT_SUCCESS(hmac_init(&ctx, key, strlen(key), hash, 0));
        hmac_update(&ctx, msg, strlen(msg));
        ASSERT_SUCCESS(hmac_final(&ctx, expected));
    }

    ASSERT_FAILURE(ordo_hmac(BLOCK_AES, 0, key, strlen(key),
                             msg, strlen(msg), out));
    ASSERT_SUCCESS(ordo_hmac(hash, 0, key, strlen(key),
                             msg, strlen(msg), out));
    ASSERT_BUF_EQ(out, expected, digest_length(hash));

    return 1;
}
