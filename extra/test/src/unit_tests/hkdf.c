/*===-- unit_tests/hkdf.c --------------------------------*- TEST -*- C -*-===*/
/**
*** @file
*** @brief Test Vectors
***
*** Unit tests for the HKDF module.
**/
/*===----------------------------------------------------------------------===*/

#include "testenv.h"

/*===----------------------------------------------------------------------===*/

int test_hkdf_precond(void);
int test_hkdf_precond(void)
{
    unsigned char key[4] = {0};
    unsigned char salt[4] = {0};
    unsigned char info[4] = {0};
    unsigned char out[4];

    /* Invalid hash function (failure) */

    ASSERT_FAILURE(kdf_hkdf(0, 0,
                            key, sizeof(key),
                            salt, sizeof(salt),
                            info, sizeof(info),
                            out, sizeof(out)));

    ASSERT_FAILURE(kdf_hkdf(BLOCK_AES, 0,
                            key, sizeof(key),
                            salt, sizeof(salt),
                            info, sizeof(info),
                            out, sizeof(out)));

    /* Zero length key (failure) */

    ASSERT_FAILURE(kdf_hkdf(HASH_SHA256, 0,
                            key, 0,
                            salt, sizeof(salt),
                            info, sizeof(info),
                            out, sizeof(out)));

    /* Zero length output (failure) */

    ASSERT_FAILURE(kdf_hkdf(HASH_SHA256, 0,
                            key, sizeof(key),
                            salt, sizeof(salt),
                            info, sizeof(info),
                            out, 0));

    /* Zero length salt (success) */

    ASSERT_SUCCESS(kdf_hkdf(HASH_SHA256, 0,
                            key, sizeof(key),
                            salt, 0,
                            info, sizeof(info),
                            out, sizeof(out)));

    /* Zero length info (success) */

    ASSERT_SUCCESS(kdf_hkdf(HASH_SHA256, 0,
                            key, sizeof(key),
                            salt, sizeof(salt),
                            info, 0,
                            out, sizeof(out)));

    {
        static unsigned char out_large[HASH_DIGEST_LEN * 255 + 1];
        prim_t hash = prim_default(PRIM_TYPE_HASH);
        size_t digest_len = digest_length(hash);

        /* Largest output length (success) */

        ASSERT_SUCCESS(kdf_hkdf(hash, 0,
                                key, sizeof(key),
                                salt, sizeof(salt),
                                info, sizeof(info),
                                out_large, digest_len * 255));

        /* Too long output length (failure) */

        ASSERT_FAILURE(kdf_hkdf(HASH_SHA256, 0,
                                key, sizeof(key),
                                salt, sizeof(salt),
                                info, sizeof(info),
                                out_large, digest_len * 255 + 1));
    }

    return 1;
}
