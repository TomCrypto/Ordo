/*===-- test/test_vectors/pbkdf2.c ---------------------*- PUBLIC -*- C -*-===*/
/**
*** @file
*** @brief Test Vectors
***
*** Test vectors for the PBKDF2 module.
**/
/*===----------------------------------------------------------------------===*/

#include "testenv.h"

/*===----------------------------------------------------------------------===*/

struct TEST_VECTOR
{
    const char *pwd;
    size_t pwd_len;
    const char *salt;
    size_t salt_len;
    size_t iterations;
    const char *out;
    size_t out_len;
    prim_t hash;
};

static const struct TEST_VECTOR tests[] =
{
{
    "password", 8,
    "salt", 4,
    1,
    "\x12\x0f\xb6\xcf\xfc\xf8\xb3\x2c\x43\xe7\x22\x52\x56\xc4\xf8\x37"
    "\xa8\x65\x48\xc9\x2c\xcc\x35\x48\x08\x05\x98\x7c\xb7\x0b\xe1\x7b", 32,
    HASH_SHA256
},
{
    "password", 8,
    "salt", 4,
    2,
    "\xae\x4d\x0c\x95\xaf\x6b\x46\xd3\x2d\x0a\xdf\xf9\x28\xf0\x6d\xd0"
    "\x2a\x30\x3f\x8e\xf3\xc2\x51\xdf\xd6\xe2\xd8\x5a\x95\x47\x4c\x43", 32,
    HASH_SHA256
},
{
    "password", 8,
    "salt", 4,
    16777216,
    "\xcf\x81\xc6\x6f\xe8\xcf\xc0\x4d\x1f\x31\xec\xb6\x5d\xab\x40\x89"
    "\xf7\xf1\x79\xe8\x9b\x3b\x0b\xcb\x17\xad\x10\xe3\xac\x6e\xba\x46", 32,
    HASH_SHA256
},
{
    "\x70\x61\x73\x73\x00\x77\x6f\x72\x64", 9,
    "\x73\x61\x00\x6c\x74", 5,
    4096,
    "\x89\xb6\x9d\x05\x16\xf8\x29\x89\x3c\x69\x62\x26\x65\x0a\x86\x87", 16,
    HASH_SHA256
},
{
    "passwordPASSWORDpassword", 24,
    "saltSALTsaltSALTsaltSALTsaltSALTsalt", 36,
    4096,
    "\x34\x8c\x89\xdb\xcb\xd3\x2b\x2f\x32\xd8\x14\xb8\x11\x6e\x84\xcf"
    "\x2b\x17\x34\x7e\xbc\x18\x00\x18\x1c\x4e\x2a\x1f\xb8\xdd\x53\xe1"
    "\xc6\x35\x51\x8c\x7d\xac\x47\xe9", 40,
    HASH_SHA256
}
};

#define MAX_OUT_LEN 40

/*===----------------------------------------------------------------------===*/

static int check(struct TEST_VECTOR test)
{
    unsigned char out[MAX_OUT_LEN];

    if (!prim_avail(test.hash))
        return 1;

    ASSERT_SUCCESS(kdf_pbkdf2(test.hash, 0,
                              test.pwd, test.pwd_len,
                              test.salt, test.salt_len,
                              test.iterations,
                              out, test.out_len));

    ASSERT_BUF_EQ(out, test.out, test.out_len);

    return 1;
}

int test_vectors_pbkdf2(void);
int test_vectors_pbkdf2(void)
{
    size_t t;

    for (t = 0; t < ARRAY_SIZE(tests); ++t)
        if (!check(tests[t])) return 0;

    return 1;
}
