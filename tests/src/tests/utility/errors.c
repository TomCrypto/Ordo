#include <tests/utility/errors.h>

int test_error_codes(char *output, int maxlen, FILE *ext)
{
    if (ORDO_SUCCESS != 0)  fail("'ORDO_SUCCESS' is not zero.");
    if (ORDO_FAIL >= 0)     fail("'ORDO_FAIL' is not negative.");
    if (ORDO_LEFTOVER >= 0) fail("'ORDO_LEFTOVER' is not negative.");
    if (ORDO_KEY_LEN >= 0)  fail("'ORDO_KEY_LEN' is not negative.");
    if (ORDO_PADDING >= 0)  fail("'ORDO_PADDING' is not negative.");
    if (ORDO_ALLOC >= 0)    fail("'ORDO_ALLOC' is not negative.");
    if (ORDO_ARG >= 0)      fail("'ORDO_ARG' is not negative.");

    pass("Error codes conform to requirements.");
}
