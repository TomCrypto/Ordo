/*===-- common/version.h -------------------------------*- PUBLIC -*- H -*-===*/
/**
*** @file
*** @brief Utility
***
*** This header exposes functionality relating to the library's version.
**/
/*===----------------------------------------------------------------------===*/

#ifndef ORDO_VERSION_H
#define ORDO_VERSION_H

/** @cond **/
#include "ordo/common/interface.h"
/** @endcond **/

#ifdef __cplusplus
extern "C" {
#endif

/*===----------------------------------------------------------------------===*/

/** @brief Library version information.
***
*** Contains version information for the library.
**/
struct ORDO_VERSION
{
    /** The version as an integer of the form XXYYZZ, e.g. 30242 == 3.2.42.
    **/
    unsigned int id;

    /** The version e.g. "2.7.0".
    **/
    const char *version;

    /** The target platform e.g. "linux".
    **/
    const char *platform;

    /** The target architecture e.g. "amd64".
    **/
    const char *arch;

    /** A string which contains version, platform and architecture.
    **/
    const char *build;

    /** A null-terminated list of targeted features.
    **/
    const char *const *features;

    /** The list of features, as a space-separated string.
    **/
    const char *feature_list;
};

/** Returns an \c ORDO_VERSION structure for this library build.
**/
ORDO_PUBLIC
const struct ORDO_VERSION *ordo_version(void);

/*===----------------------------------------------------------------------===*/

#ifdef __cplusplus
}
#endif

#endif
