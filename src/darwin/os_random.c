/*===-- os_random.c ------------------------------------*- darwin -*- C -*-===*/

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

#include "ordo/misc/os_random.h"

#include <stdio.h>

/*===----------------------------------------------------------------------===*/

int os_random(void *out, size_t len)
{
    FILE *f = fopen("/dev/urandom", "r");
    if (!f) return ORDO_FAIL;

    while (len != 0)
    {
        size_t read = fread(out, 1, len, f);
        if (read == 0)
        {
            fclose(f);
            return ORDO_FAIL;
        }

        out = offset(out, read);
        len -= read;
    }

    fclose(f);

    return ORDO_SUCCESS;
}

int os_secure_random(void *out, size_t len)
{
    return os_random(out, len);
}
