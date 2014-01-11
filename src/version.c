//===-- version.c -------------------------------------*- generic -*- C -*-===//

#include "ordo/common/version.h"

/// @cond
#include "ordo/internal/implementation.h"
/// @endcond

//===----------------------------------------------------------------------===//

#define VERSION "2.6.0"

const char *ordo_build_tag(void)
{
    return "ordo-"VERSION"-"ORDO_SYSTEM"-"ORDO_ARCH
    #if defined(ORDO_HAS_FEATURES)
    " ["ORDO_FEATURES"]"
    #endif
    ;
}
