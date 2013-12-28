//===-- internal/implementation.h----------------------*- INTERNAL-*- H -*-===//
///
/// @file
/// @internal
/// @brief \b Internal, API
///
/// This header contains some compiler-dependent macros, for  defining various
/// semantics  which the users of this  library should not depend on. It is an
/// error to include this header in any code outside the Ordo implementation.
///
/// Every source file will include this header.
///
//===----------------------------------------------------------------------===//

#ifndef ORDO_IMPLEMENTATION_H
#define ORDO_IMPLEMENTATION_H

/// @cond
#include "ordo/common/error.h"
#include "ordo/common/query.h"
#include "ordo/internal/mem.h"
#include "ordo/internal/alg.h"
#include "ordo/internal/sys.h"

#include <stdlib.h>
#include <string.h>
/// @endcode

//===----------------------------------------------------------------------===//

#if !(defined(BUILDING_ORDO) || defined(BUILDING_ordo))
    #error "This header is reserved for the Ordo library implementation."
#endif

#if defined(__clang__) || defined(__GNUC__) || defined(__MINGW32__)
    #define _align_(x) __attribute__((aligned(x)))
#elif defined(_MSC_VER)
    #define _align_(x) __declspec(align(x))
#endif

#if defined(__clang__)
    #define _hot_ __attribute__((hot))
    #define _cold_ __attribute__((cold))
#elif defined(__GNUC__) || defined(__MINGW32__)
    #define GCC_VERSION (__GNUC__ * 10000     \
                       + __GNUC_MINOR__ * 100 \
                       + __GNUC_PATCHLEVEL__)

    #if GCC_VERSION >= 40300 // >= v4.3 support needed
        #define _hot_ __attribute__((hot))
        #define _cold_ __attribute__((cold))
    #else
        #define _hot_
        #define _cold_
    #endif

    #undef GCC_VERSION
#elif defined(_MSC_VER)
    #define _hot_
    #define _cold_
#endif

//===----------------------------------------------------------------------===//

#endif
