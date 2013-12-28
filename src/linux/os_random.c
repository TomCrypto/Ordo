//===-- os_random.c --------------------------------------*- unix -*- C -*-===//

#include "ordo/misc/os_random.h"

/// @cond
#include "ordo/internal/implementation.h"
/// @endcond

#include <stdio.h>

//===----------------------------------------------------------------------===//

int os_random(void *buffer, size_t size)
{
    FILE* f = fopen("/dev/urandom", "r");
    if (!f) return ORDO_FAIL;

    while (size != 0)
    {
        size_t len = fread(buffer, 1, size, f);
        if (len == 0)
        {
            fclose(f);
            return ORDO_FAIL;
        }

        buffer = offset(buffer, len);
        size -= len;
    }

    fclose(f);

    return ORDO_SUCCESS;
}
