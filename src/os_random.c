//===-- os_random.c -----------------------------------*- generic -*- C -*-===//

#include "ordo/misc/os_random.h"

/// @cond
#include "ordo/internal/implementation.h"
/// @endcond

//===----------------------------------------------------------------------===//

int os_random(void *buffer, size_t size)
{
    return ORDO_FAIL; // This is supposed to be overriden
}
