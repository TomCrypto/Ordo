/*===-- os_random.c -------------------------------*- shared/unix -*- C -*-===*/

#include "ordo/misc/os_random.h"

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

#include <stdio.h>

/*===----------------------------------------------------------------------===*/

static int read_file(const char *file, void *out, size_t len)
{
    FILE *f = fopen(file, "r");
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

int os_random(void *out, size_t len)
{
    return read_file("/dev/urandom", out, len);
}

int os_secure_random(void *out, size_t len)
{
    return read_file("/dev/random", out, len);
}
