#ifndef TESTS_H
#define TESTS_H

/* This is a test prototype. The test should return 0 on failure, 1 on success
 * and should print out a very short and informative tag (if required, e.g. on
 * error) to the tag buffer, which will be displayed next to the test name.
*/
typedef int (*TEST_FUNC)(char *tag);

struct TEST
{
    const char *name;
    TEST_FUNC test;
};

struct TEST_SUITE
{
    struct TEST *list;
    size_t test_count;
    const char *suite;
};

#define TEST_COUNT(x) (sizeof(x) / sizeof(struct TEST))

#if defined(ORDO_STATIC_LIB)

extern int test_mem(void);
extern int test_alg(void);
extern int test_sys(void);
extern int test_macros(void);
extern int test_pad_check(void);
extern int test_xor_buffer(void);
extern int test_inc_buffer(void);

static struct TEST tests_internal[] =
{
    { (TEST_FUNC)test_alg, "Internal functions" },
    { (TEST_FUNC)test_sys, "System utilities" },
    { (TEST_FUNC)test_pad_check, "pad_check function" },
    { (TEST_FUNC)test_xor_buffer, "xor_buffer function" },
    { (TEST_FUNC)test_inc_buffer, "inc_buffer function" },
    { (TEST_FUNC)test_macros, "Library macros" },
};

#endif

extern int test_error_codes(void);

static struct TEST tests_utils[] =
{
    { (TEST_FUNC)test_error_codes, "Error codes" },
};

extern int test_os_random(void);

static struct TEST tests_misc[] =
{
    { (TEST_FUNC)test_os_random, "System CSPRNG" },
};

extern int test_block(void);
extern int test_block_utilities(void);

static struct TEST tests_block[] =
{
    { (TEST_FUNC)test_block, "Block cipher test vectors" },
    { (TEST_FUNC)test_block_utilities, "Block cipher utilities" },
};

extern int test_block_modes(void);
extern int test_block_modes_utilities(void);

static struct TEST tests_block_mode[] =
{
    { (TEST_FUNC)test_block_modes, "Block cipher mode test vectors" },
    { (TEST_FUNC)test_block_modes_utilities, "Block cipher mode utilities" },
};

extern int test_digest(void);
extern int test_digest_utilities(void);
extern int test_skein256(void);

static struct TEST tests_digest[] =
{
    { (TEST_FUNC)test_digest, "Hash function test vectors" },
    { (TEST_FUNC)test_digest_utilities, "Hash function utilities" },
    { (TEST_FUNC)test_skein256, "Skein-256 extended test vectors" },
};

extern int test_hmac(void);

static struct TEST tests_hmac[] =
{
    { (TEST_FUNC)test_hmac, "HMAC test vectors" },
};

extern int test_pbkdf2(void);

static struct TEST tests_kdf[] =
{
    { (TEST_FUNC)test_pbkdf2, "PBKDF2 test vectors" },
};

extern int test_stream(void);
extern int test_stream_utilities(void);

extern int test_enc_stream_algorithm(void);
extern int test_enc_stream_interface(void);

static struct TEST tests_stream[] =
{
    { (TEST_FUNC)test_stream, "Stream cipher test vectors" },
    { (TEST_FUNC)test_stream_utilities, "Stream cipher utilities" },
    { (TEST_FUNC)test_enc_stream_algorithm, "Stream encryption test vectors" },
    { (TEST_FUNC)test_enc_stream_interface, "Stream encryption module" },
};

extern int test_curve25519(void);

static struct TEST tests_misc_modules[] =
{
    { (TEST_FUNC)test_curve25519, "Curve25519 test vectors" }
};

static struct TEST_SUITE TESTS[] =
{
    #if defined(ORDO_STATIC_LIB)
    { tests_internal, TEST_COUNT(tests_internal), "Internal utilities" },
    #endif
    
    { tests_utils, TEST_COUNT(tests_utils), "Library utilities" },
    
    { tests_misc, TEST_COUNT(tests_misc), "Miscellaneous" },
    
    { tests_block, TEST_COUNT(tests_block), "Block cipher primitives" },
    
    { tests_block_mode, TEST_COUNT(tests_block_mode), "Block cipher mode primitives" },
    
    { tests_digest, TEST_COUNT(tests_digest), "Hash function primitives" },
    
    { tests_hmac, TEST_COUNT(tests_hmac), "HMAC module" },
    
    { tests_kdf, TEST_COUNT(tests_kdf), "KDF module" },
    
    { tests_stream, TEST_COUNT(tests_stream), "Stream cipher primitives" },

    { tests_misc_modules, TEST_COUNT(tests_misc_modules), "Miscellaneous modules" }
};

#define SUITE_COUNT (sizeof(TESTS) / sizeof(struct TEST_SUITE))

#endif
