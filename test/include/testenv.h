#ifndef TESTENV_H
#define TESTENV_H

#include <stdlib.h>
#include <stdint.h>

enum LOG_COLOR
{
    BLACK,
    RED,
    GREEN,
    YELLOW,
    BLUE,
    MAGENTA,
    CYAN,
    WHITE
};

/* Colorizes a string using a given color and optionally uses a bold font. The
 * returned string should be IMMEDIATELY printed to standard output as it will
 * be garbage-collected eventually. Do not free it yourself. You must not hold
 * a reference to it, and this function is not thread-safe.
*/
const char *colorize(const char *str, enum LOG_COLOR color, int bold);

#define   black(str)    colorize(str, BLACK,   0)
#define   red(str)      colorize(str, RED,     0)
#define   green(str)    colorize(str, GREEN,   0)
#define   yellow(str)   colorize(str, YELLOW,  0)
#define   blue(str)     colorize(str, BLUE,    0)
#define   magenta(str)  colorize(str, MAGENTA, 0)
#define   cyan(str)     colorize(str, CYAN,    0)
#define   white(str)    colorize(str, WHITE,   0)

#define  bblack(str)    colorize(str, BLACK,   1)
#define  bred(str)      colorize(str, RED,     1)
#define  bgreen(str)    colorize(str, GREEN,   1)
#define  byellow(str)   colorize(str, YELLOW,  1)
#define  bblue(str)     colorize(str, BLUE,    1)
#define  bmagenta(str)  colorize(str, MAGENTA, 1)
#define  bcyan(str)     colorize(str, CYAN,    1)
#define  bwhite(str)    colorize(str, WHITE,   1)

enum LOG_STATUS
{
    PASS, /* A test passes successfully - not used by the driver. */
    FAIL, /* A test fails - please, only once per group of tests. */
    WARN, /* Indicate a serious, but not catastrophic, condition. */
    INFO  /* Report a relevant but harmless message for the user. */
};

/* Prints a line to the log with the given status with optional formatting but
 * please note that you should really only output a short informative line via
 * this function (<= 70 chars), hence a newline is automatically appended.
 *
 * Note this is purely informative and doesn't actually tell the driver if the
 * tests failed (hence it is possible to print a pass while actually failing &
 * vice versa). The success condition is reported by the test's return value.
*/
void lprintf(enum LOG_STATUS status, const char *fmt, ...);

struct DRIVER_OPTIONS
{
    int color;          /* Whether to setup the log with colors or not. */
};

/* Initializes the test driver, sets up the output log, runs all tests, before
 * returning depending on whether the tests passed. It accepts a configuration
 * structure (the opt struct) which can be populated from the command-line.
 *
 * Returns 0 on failure (any test failed) and 1 on success.
*/
int run_test_driver(struct DRIVER_OPTIONS opt);

/* These are shortcuts for passing/failing tests for simple strings. */

#define PASS(...) \
    do { lprintf(PASS, __VA_ARGS__); return 1; } while (0)

#define FAIL(...) \
    do { lprintf(FAIL, __VA_ARGS__); return 0; } while (0)

#define WARN(...) \
    do { lprintf(WARN, __VA_ARGS__);           } while (0)

#define INFO(...) \
    do { lprintf(INFO, __VA_ARGS__);           } while (0)

/* These are some assertion macros, which tests can use if required. */

#define ASSERT(x, ...) \
    do { if (!(x)) FAIL(__VA_ARGS__); } while (0)

#define ASSERT_EQ(x, e, ...) \
    do { if ((x) != (e)) FAIL(__VA_ARGS__); } while (0)

#define ASSERT_NE(x, e, ...) \
    do { if ((x) == (e)) FAIL(__VA_ARGS__); } while (0)

/* These are convenience macros which tests may wish to make use of. */

#define random(N) (rand() % N)


static unsigned char scratch[1024];

#endif
