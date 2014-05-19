/*===-- common/interface.h -----------------------------*- PUBLIC -*- H -*-===*/
/**
/// @file
/// @brief API
///
/// This header contains  some preprocessor  definitions which try to abstract
/// compiler-specific features  (such as packing, export  mechanisms, hot code
/// sections), and will be included in every other header in the library.
**/
/*===----------------------------------------------------------------------===*/

#ifndef ORDO_INTERFACE_H
#define ORDO_INTERFACE_H

/** @cond **/
#include <stddef.h>
#include <stdint.h>
/** @endcond **/

/*===----------------------------------------------------------------------===*/

#include "ordo/common/identification.h"
#include "ordo/platform.h"

/*===----------------------------------------------------------------------===*/

#if defined(BUILDING_ORDO) || defined(BUILDING_ordo)
    #if defined(ORDO_EXPORTS) || defined(ordo_EXPORTS)
        #define BUILD_SHARED
    #endif
#else
    #if !defined(ORDO_STATIC_LIB)
        #define USING_SHARED
    #endif
#endif

#if defined(__MINGW32__) || defined(_MSC_VER)
    #if defined(BUILD_SHARED)
        #define ORDO_PUBLIC __declspec(dllexport)
        #define ORDO_HIDDEN
    #elif defined(USING_SHARED)
        #define ORDO_PUBLIC __declspec(dllimport)
        #define ORDO_HIDDEN
    #else
        #define ORDO_PUBLIC
        #define ORDO_HIDDEN
    #endif
#elif defined(__clang__) || defined(__GNUC__)
    #if defined(BUILD_SHARED)
        #define ORDO_PUBLIC __attribute__((visibility("default")))
        #define ORDO_HIDDEN __attribute__((visibility("hidden")))
    #elif defined(USING_SHARED)
        #define ORDO_PUBLIC __attribute__((visibility("default")))
        #define ORDO_HIDDEN __attribute__((visibility("hidden")))
    #else
        #define ORDO_PUBLIC
        #define ORDO_HIDDEN
    #endif
#else
    #error "Unsupported compiler!"
#endif

#undef BUILD_SHARED
#undef USING_SHARED

/*===----------------------------------------------------------------------===*/

#endif
