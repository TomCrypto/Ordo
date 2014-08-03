/*===-- unit_tests/misc.c --------------------------------*- TEST -*- C -*-===*/
/**
*** @file
*** @brief Test Vectors
***
*** This unit tests miscellaneous library utilities.
**/
/*===----------------------------------------------------------------------===*/

#include "testenv.h"

/*===----------------------------------------------------------------------===*/

int test_error_codes(void);
int test_error_codes(void)
{
    ASSERT_EQ(ORDO_SUCCESS,  0);
    ASSERT_NE(ORDO_FAIL,     0);
    ASSERT_NE(ORDO_LEFTOVER, 0);
    ASSERT_NE(ORDO_KEY_LEN,  0);
    ASSERT_NE(ORDO_PADDING,  0);
    ASSERT_NE(ORDO_ARG,      0);
    
    return 1;
}

static uint8_t pow257(uint8_t x, uint8_t n)
{
    uint16_t r = 1;
    while (n--) r = (r * x) % 257;
    return (uint8_t)r;
}

int test_ctcmp(void);
int test_ctcmp(void)
{
    #define BUFLEN 1024
    unsigned char buf1[BUFLEN], buf2[BUFLEN];
    size_t t, n;

    for (n = 0; n < 1024; ++n)
        for (t = 0; t < 256; ++t)
        {
            memset(buf1, (uint8_t)t, BUFLEN);
            memset(buf2, (uint8_t)t, BUFLEN);

            ASSERT(ctcmp(buf1, buf2, BUFLEN));
        }

    for (n = 0; n < 1024; ++n)
        for (t = 0; t < 256; ++t)
        {
            uint8_t t2 = pow257(5, (uint8_t)t);

            memset(buf1, (uint8_t)t, BUFLEN);
            memset(buf2, t2,         BUFLEN);

            ASSERT(ctcmp(buf1, buf2, BUFLEN) == ((uint8_t)t == t2));
        }

    return 1;
}
