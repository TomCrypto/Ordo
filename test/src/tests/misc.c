#include "testenv.h"

#include <string.h>
#include "ordo.h"

int test_error_codes(void)
{
    ASSERT_EQ(ORDO_SUCCESS,  0, "%s isn't zero.", byellow("ORDO_SUCCESS"));
    ASSERT_NE(ORDO_FAIL,     0, "%s is zero.",    byellow("ORDO_FAIL"));
    ASSERT_NE(ORDO_LEFTOVER, 0, "%s is zero.",    byellow("ORDO_LEFTOVER"));
    ASSERT_NE(ORDO_KEY_LEN,  0, "%s is zero.",    byellow("ORDO_KEY_LEN"));
    ASSERT_NE(ORDO_PADDING,  0, "%s is zero.",    byellow("ORDO_PADDING"));
    ASSERT_NE(ORDO_ARG,      0, "%s is zero.",    byellow("ORDO_ARG"));
    
    return 1;
}
