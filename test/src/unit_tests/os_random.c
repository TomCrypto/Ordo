/*===-- test/unit_tests/os_random.c --------------------*- PUBLIC -*- C -*-===*/
/**
*** @file
*** @brief Test Vectors
***
*** This unit does rudimentary testing on the os_random module.
**/
/*===----------------------------------------------------------------------===*/

#include "testenv.h"

/*===----------------------------------------------------------------------===*/

int test_os_random(void);
int test_os_random(void)
{
    uint8_t buffer[1024] = {0};
    size_t t;

    ASSERT_SUCCESS(os_random(&buffer, sizeof(buffer)));

    for (t = 0; t < sizeof(buffer); ++t)
        if (buffer[t] != 0) return 1;

    ASSERT(0);
}
