/*===-- os_random.c -----------------------------------*- generic -*- C -*-===*/

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

#include "ordo/misc/os_random.h"

/*===----------------------------------------------------------------------===*/

int os_random(void *out, size_t len)
{
    return ORDO_FAIL; /* This is supposed to be overridden */
}

int os_secure_random(void *out, size_t len)
{
    return ORDO_FAIL;
}
