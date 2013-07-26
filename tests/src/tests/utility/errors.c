#include "tests/utility/errors.h"

int test_error_codes(char *output, size_t maxlen, FILE *ext)
{
    if (ORDO_SUCCESS != 0)  fail("'ORDO_SUCCESS' is not zero.");

    pass("Error codes conform to requirements.");
}
