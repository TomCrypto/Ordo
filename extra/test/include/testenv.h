/*===-- testenv.h ----------------------------------------*- TEST -*- H -*-===*/
/**
*** @file
*** @brief Test Utilities
***
*** This header contains some utilities used by the tests, for instance common
*** includes, some assertion macros, compile-time helper macros, and so on.
**/
/*===----------------------------------------------------------------------===*/

#ifndef TESTENV_H
#define TESTENV_H

/** @cond **/
#include <stddef.h>
#include <stdint.h>
#include <string.h>
/** @endcond **/

#include "ordo.h"

/*===----------------------------------------------------------------------===*/

/* These are some assertion macros, which tests can use if required. */

#define ASSERT(x) \
    do { if (!(x)) return 0; } while (0)

#define ASSERT_EQ(x, e) \
    do { if ((x) != (e)) return 0; } while (0)

#define ASSERT_NE(x, e) \
    do { if ((x) == (e)) return 0; } while (0)

#define ASSERT_SUCCESS(retval) \
    do { if (retval) return 0; } while (0)

#define ASSERT_FAILURE(retval) \
    do { if (!retval) return 0; } while (0)

#define ASSERT_BUF_EQ(x, e, len) \
    do { if (memcmp(x, e, len) != 0) return 0; } while (0)

/* These are convenience macros which tests may wish to make use of. */

#define ARRAY_SIZE(X) (sizeof((X)) / sizeof(*(X)))

#endif
