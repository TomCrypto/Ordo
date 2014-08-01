/*===-- unit_tests/os_random.c ---------------------------*- TEST -*- C -*-===*/
/**
*** @file
*** @brief Test Vectors
***
*** This unit does rudimentary testing on the os_random module.
***
*** Note: this unit test will do nothing if the library is built for a generic
*** platform, as there is of course no os_random implementation in that case.
**/
/*===----------------------------------------------------------------------===*/

#include "testenv.h"

/*===----------------------------------------------------------------------===*/

int test_os_random(void);
int test_os_random(void)
{
    if (strcmp(ordo_version()->system, "generic"))
    {
        uint8_t buffer[1024] = {0};
        size_t t;

        ASSERT_SUCCESS(os_random(&buffer, sizeof(buffer)));

        for (t = 0; t < sizeof(buffer); ++t)
            if (buffer[t] != 0) return 1;

        return 0;
    }

    return 1;
}
