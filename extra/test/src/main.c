/*===-- main.c -------------------------------------------*- TEST -*- C -*-===*/
/**
*** @file
*** @brief Test Driver
***
*** This is the test driver for Ordo which runs a series of tests ranging from
*** algorithm test vectors to tests designed to check API behaviour. The array
*** of tests is in this file and can be easily extended to add more tests.
***
*** The \c term_rewind() function is meant to back to the start of the current
*** line, then up one character (to redraw on top of the previous iteration).
***
*** The \c term_tty() function should check whether standard output is a valid
*** tty or something else (like a file) to decide which output format to use.
***
*** The \c TERMW macro must contain the width of the terminal in characters.
**/
/*===----------------------------------------------------------------------===*/

#include <stdlib.h>
#include <stdio.h>

#include "testenv.h"

/*===---------------------------- TEST ARRAY ----------------------------===*/

typedef int (* TEST_FUNCTION)(void);

struct TEST
{
    TEST_FUNCTION fn;
    const char *name;
};

/* Reference your test functions below. */

static int test_init(void) { return 1; }
static int test_fini(void) { return 1; }

extern int test_vectors_md5(void);
extern int test_vectors_sha1(void);
extern int test_vectors_sha256(void);
extern int test_vectors_skein256(void);
extern int test_vectors_hmac(void);
extern int test_vectors_hkdf(void);
extern int test_vectors_pbkdf2(void);
extern int test_vectors_rc4(void);
extern int test_vectors_aes(void);
extern int test_vectors_threefish256(void);
extern int test_vectors_ecb(void);
extern int test_vectors_cbc(void);
extern int test_vectors_ctr(void);
extern int test_vectors_cfb(void);
extern int test_vectors_ofb(void);
extern int test_vectors_curve25519(void);

#if defined(ORDO_STATIC_LIB)
extern int test_macros(void);
extern int test_pad_check(void);
extern int test_xor_buffer(void);
extern int test_inc_buffer(void);
#endif

extern int test_error_codes(void);
extern int test_ctcmp(void);
extern int test_os_random(void);

/* Add & name your test functions here. */

static const struct TEST tests[] =
{
    { test_init,                         "Initialization"                   },
    #if defined(ORDO_STATIC_LIB)
    { test_macros,                       "Macro tests"                      },
    { test_pad_check,                    "pad_check tests"                  },
    { test_xor_buffer,                   "xor_buffer tests"                 },
    { test_inc_buffer,                   "inc_buffer tests"                 },
    #endif
    { test_vectors_md5,                  "MD5 test vectors"                 },
    { test_vectors_sha1,                 "SHA-1 test vectors"               },
    { test_vectors_sha256,               "SHA-256 test vectors"             },
    { test_vectors_skein256,             "Skein-256 test vectors"           },
    { test_vectors_hmac,                 "HMAC test vectors"                },
    { test_vectors_hkdf,                 "HKDF test vectors"                },
    { test_vectors_pbkdf2,               "PBKDF2 test vectors"              },
    { test_vectors_rc4,                  "RC4 test vectors"                 },
    { test_vectors_aes,                  "AES test vectors"                 },
    { test_vectors_threefish256,         "Threefish-256 test vectors"       },
    { test_vectors_ecb,                  "ECB test vectors"                 },
    { test_vectors_cbc,                  "CBC test vectors"                 },
    { test_vectors_ctr,                  "CTR test vectors"                 },
    { test_vectors_cfb,                  "CFB test vectors"                 },
    { test_vectors_ofb,                  "OFB test vectors"                 },
    { test_vectors_curve25519,           "Curve25519 test vectors"          },
    { test_error_codes,                  "Error code tests"                 },
    { test_ctcmp,                        "Constant-time comparison tests"   },
    { test_os_random,                    "os_random tests"                  },
    { test_fini,                         "All tests completed"              }
};

/*===------------------------ TERMINAL UTILITIES ------------------------===*/

#if defined(_WIN32)
#include <windows.h>
#define TERMW 79 /* 80 doesn't work, because cmd.exe. */
#define PAD_LINE_L "==================================="
#define PAD_LINE_R "=================================="
#else
#define TERMW 80
#define PAD_LINE_L "==================================="
#define PAD_LINE_R "==================================="
#endif

static void term_rewind(void)
{
	#if defined(_WIN32)
	HANDLE handle = GetStdHandle(STD_OUTPUT_HANDLE);
	CONSOLE_SCREEN_BUFFER_INFO info; COORD coord;
	GetConsoleScreenBufferInfo(handle, &info);

	coord.X = 0;
	coord.Y = info.dwCursorPosition.Y - 1;

	SetConsoleCursorPosition(handle, coord);
	#else
    printf("\r\033[1A");
	#endif
}

#if defined(_WIN32)
#include <io.h>
#else
#include <unistd.h>
#endif

static int term_tty(void)
{
    #if defined(_MSC_VER)
    #define STDOUT_FILENO 1
    return _isatty(STDOUT_FILENO);
    #else
    return isatty(STDOUT_FILENO);
    #endif
}

/*===------------------------- TEST DRIVER CODE -------------------------===*/

static void show_progress(size_t pos, size_t total)
{
    if (!total) /* One test has failed. */
    {
        printf("[");
        printf(PAD_LINE_L);
        printf(" FAILED ");
        printf(PAD_LINE_R);
        printf("]\n");
    }
    else if (pos == total) /* Finished. */
    {
        printf("[");
        printf(PAD_LINE_L);
        printf(" PASSED ");
        printf(PAD_LINE_R);
        printf("]\n");
    }
    else /* Working, draw progress bar. */
    {
        size_t pivot = (pos * (TERMW - 2)) / total;
        size_t t;

        printf("[");

        for (t = 0; t < TERMW - 2; ++t)
        {
            switch (t < pivot ? -1 : t > pivot)
            {
                case -1: printf("="); break;
                case  0: printf(">"); break;
                case +1: printf(" "); break;
            }
        }

        printf("]");
		fflush(stdout);
    }
}

static int test_tty(void)
{
    const char *version = ordo_version()->build;
    unsigned verlen = (unsigned)strlen(version);
    size_t t;

    for (t = 0; t < ARRAY_SIZE(tests); ++t)
    {
        if (t > 0) term_rewind();

        printf("< Testing %s :: %*s >\n", version,
               TERMW - 16 - verlen, tests[t].name);

        if (!tests[t].fn())
        {
            show_progress(0, 0);
            return EXIT_FAILURE;
        }

        show_progress(t + 1, ARRAY_SIZE(tests));
    }

    return EXIT_SUCCESS;
}

static int test_notty(void)
{
    const char *version = ordo_version()->build;
    size_t t;

    printf("Testing %s...\n\n", version);

    for (t = 0; t < ARRAY_SIZE(tests); ++t)
    {
        printf("  %s :: ", tests[t].name);

        if (!tests[t].fn())
        {
            printf("FAILED\n");
            return EXIT_FAILURE;
        }

        printf("PASSED\n");
    }

    printf("\n");
    return EXIT_SUCCESS;
}

int main(void)
{
    if (term_tty())
        return test_tty();
    else
        return test_notty();
}
