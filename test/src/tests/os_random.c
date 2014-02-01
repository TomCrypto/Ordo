#include "testenv.h"

#include <string.h>
#include "ordo.h"

int test_os_random(void)
{
    uint8_t buffer[1024];
    int t;

    memset(buffer, 0x00, sizeof(buffer));
    if (os_random(&buffer, sizeof(buffer)))
    {
        FAIL("'os_random' reported failure (does OS provide one?)");
    }

    /* Just do a rudimentary check that the buffer was actually changed. */
    for (t = 0; t < 1024; ++t)
    {
        if (buffer[t] != 0) return 1;
    }

    /* Chances of a false positive are 256^(-1024) (read: non-existent). */
    FAIL("'os_random' reports success but non-random output.");
}
