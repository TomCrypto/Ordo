#ifndef TESTS_H
#define TESTS_H

/* A test returns 0 on failure, 1 on success. It can output text to the log by
 * using the lprintf() function (other output methods are _not_ recommended as
 * they tend to garble the screen). Tests shouldn't output whether they passed
 * or not, as the test driver takes care of this, therefore just return 1 or 0
 * as needed. However, tests should print out any relevant information.
*/
typedef int (*TEST_FUNCTION)(void);

struct TEST
{
    TEST_FUNCTION run;
    const char *name;
};

struct TEST_GROUP
{
    struct TEST *list;
    size_t test_count;
    const char *group;
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
    { (TEST_FUNCTION)test_alg, "Internal functions" },
    { (TEST_FUNCTION)test_sys, "System utilities" },
    { (TEST_FUNCTION)test_pad_check, "pad_check function" },
    { (TEST_FUNCTION)test_xor_buffer, "xor_buffer function" },
    { (TEST_FUNCTION)test_inc_buffer, "inc_buffer function" },
    { (TEST_FUNCTION)test_macros, "Library macros" },
};

#endif

extern int test_error_codes(void);

static struct TEST tests_utils[] =
{
    { (TEST_FUNCTION)test_error_codes, "Error codes" },
};

extern int test_os_random(void);

static struct TEST tests_misc[] =
{
    { (TEST_FUNCTION)test_os_random, "System CSPRNG" },
};

extern int test_block(void);
extern int test_block_utilities(void);

static struct TEST tests_block[] =
{
    { (TEST_FUNCTION)test_block, "Block cipher test vectors" },
    { (TEST_FUNCTION)test_block_utilities, "Block cipher utilities" },
};

extern int test_block_modes(void);
extern int test_block_modes_utilities(void);

static struct TEST tests_block_mode[] =
{
    { (TEST_FUNCTION)test_block_modes, "Block cipher mode test vectors" },
    { (TEST_FUNCTION)test_block_modes_utilities, "Block cipher mode utilities" },
};

extern int test_digest(void);
extern int test_digest_utilities(void);
extern int test_skein256(void);

static struct TEST tests_digest[] =
{
    { (TEST_FUNCTION)test_digest, "Hash function test vectors" },
    { (TEST_FUNCTION)test_digest_utilities, "Hash function utilities" },
    { (TEST_FUNCTION)test_skein256, "Skein-256 extended test vectors" },
};

extern int test_hmac(void);

static struct TEST tests_hmac[] =
{
    { (TEST_FUNCTION)test_hmac, "HMAC test vectors" },
};

extern int test_pbkdf2(void);

static struct TEST tests_kdf[] =
{
    { (TEST_FUNCTION)test_pbkdf2, "PBKDF2 test vectors" },
};

extern int test_stream(void);
extern int test_stream_utilities(void);

extern int test_enc_stream_algorithm(void);
extern int test_enc_stream_interface(void);

static struct TEST tests_stream[] =
{
    { (TEST_FUNCTION)test_stream, "Stream cipher test vectors" },
    { (TEST_FUNCTION)test_stream_utilities, "Stream cipher utilities" },
    { (TEST_FUNCTION)test_enc_stream_algorithm, "Stream encryption test vectors" },
    { (TEST_FUNCTION)test_enc_stream_interface, "Stream encryption module" },
};

extern int test_curve25519(void);

static struct TEST tests_misc_modules[] =
{
    { (TEST_FUNCTION)test_curve25519, "Curve25519 test vectors" }
};

static struct TEST_GROUP TESTS[] =
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

#define GROUP_COUNT (sizeof(TESTS) / sizeof(struct TEST_GROUP))

#endif
