/*===-- version.c -------------------------------------*- generic -*- C -*-===*/

/** @cond **/
#include "ordo/internal/implementation.h"
/** @endcond **/

#include "ordo/common/version.h"

/*===----------------------------------------------------------------------===*/

#define MAJ 0
#define MIN 4
#define REV 0

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

#define VERSION STR(MAJ) "." STR(MIN) "." STR(REV)
#define VERSION_ID (MAJ * 10000 + MIN * 100 + REV)

static const char *const features[] =
{
    #if defined(ORDO_HAS_FEATURES)
    ORDO_FEATURE_ARRAY
    #endif
    0
};

static const struct ORDO_VERSION version =
{
    VERSION_ID,
    VERSION,
    ORDO_SYSTEM,
    #if defined(ORDO_ARCH)
    ORDO_ARCH,
    #else
    "generic",
    #endif
    "ordo-"VERSION"-"ORDO_SYSTEM
    #if defined(ORDO_ARCH)
    "-"ORDO_ARCH
    #endif
    ,
    features,
    #if defined(ORDO_HAS_FEATURES)
    ORDO_FEATURE_LIST
    #else
    ""
    #endif
};

const struct ORDO_VERSION *ordo_version(void)
{
    return &version;
}
