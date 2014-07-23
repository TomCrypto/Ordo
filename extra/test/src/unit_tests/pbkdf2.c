/*===-- unit_tests/pbkdf2.c ------------------------------*- TEST -*- C -*-===*/
/**
*** @file
*** @brief Test Vectors
***
*** Unit tests for the PBKDF2 module.
**/
/*===----------------------------------------------------------------------===*/

#include "testenv.h"

/*===----------------------------------------------------------------------===*/

int test_pbkdf2_precond(void);
int test_pbkdf2_precond(void)
{
    unsigned char pwd[4] = {0};
    unsigned char salt[4] = {0};
    unsigned char out[4];

    /* Invalid hash function (failure) */

    ASSERT_FAILURE(kdf_pbkdf2(0, 0,
                              pwd, sizeof(pwd),
                              salt, sizeof(salt),
                              1,
                              out, sizeof(out)));

    ASSERT_FAILURE(kdf_pbkdf2(BLOCK_AES, 0,
                              pwd, sizeof(pwd),
                              salt, sizeof(salt),
                              1,
                              out, sizeof(out)));

    /* Zero iterations (failure) */

    ASSERT_FAILURE(kdf_pbkdf2(HASH_SHA256, 0,
                              pwd, sizeof(pwd),
                              salt, sizeof(salt),
                              0,
                              out, sizeof(out)));

    /* Zero length password (failure) */

    ASSERT_FAILURE(kdf_pbkdf2(HASH_SHA256, 0,
                              pwd, 0,
                              salt, sizeof(salt),
                              1,
                              out, sizeof(out)));

    /* Zero length output (failure) */

    ASSERT_FAILURE(kdf_pbkdf2(HASH_SHA256, 0,
                              pwd, sizeof(pwd),
                              salt, sizeof(salt),
                              1,
                              out, 0));

    /* Zero length salt (success) */

    ASSERT_SUCCESS(kdf_pbkdf2(HASH_SHA256, 0,
                              pwd, sizeof(pwd),
                              salt, 0,
                              1,
                              out, sizeof(out)));

    return 1;
}
