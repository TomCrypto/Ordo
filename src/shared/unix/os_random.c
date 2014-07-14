/*===-- os_random.c -------------------------------*- shared/unix -*- C -*-===*/

#include "ordo/misc/os_random.h"

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

#include <stdio.h>

/*===----------------------------------------------------------------------===*/

static int read_file(const char *path, void *out, size_t len)
{
    FILE *f = fopen(path, "rb");

    if (f)
    {
        size_t cnt = fread(out, len, 1, f);
        fclose(f); /* Do not error-check. */
        return cnt ? ORDO_SUCCESS : ORDO_FAIL;
    }

    return ORDO_FAIL;
}

int os_random(void *out, size_t len)
{
    return read_file("/dev/urandom", out, len);
}

int os_secure_random(void *out, size_t len)
{
    return read_file("/dev/random", out, len);
}
