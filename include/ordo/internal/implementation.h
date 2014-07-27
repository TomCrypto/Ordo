/*===-- internal/implementation.h---------------------*- INTERNAL -*- H -*-===*/
/**
*** @file
*** @internal
*** @brief \b Internal, API
***
*** This header contains some compiler-dependent macros, for  defining various
*** semantics  which the users of this  library should not depend on. It is an
*** error to include this header in any code outside the Ordo implementation.
***
*** Every source file will include this header.
**/
/*===----------------------------------------------------------------------===*/

#ifndef ORDO_IMPLEMENTATION_H
#define ORDO_IMPLEMENTATION_H

/*===----------------------------------------------------------------------===*/

#if !(defined(ORDO_INTERNAL_ACCESS) && defined(ORDO_STATIC_LIB))
    #if !(defined(BUILDING_ORDO) || defined(BUILDING_ordo))
        #error "This header is internal to the Ordo library."
    #endif
#endif

/* Internal function namespacing to prevent static name conflicts. */

#define rol16                            ordo_rol16_internal
#define ror16                            ordo_ror16_internal
#define rol32                            ordo_rol32_internal
#define ror32                            ordo_ror32_internal
#define rol64                            ordo_rol64_internal
#define ror64                            ordo_ror64_internal
#define smin                             ordo_smin_internal
#define smax                             ordo_smax_internal
#define pswap8                           ordo_pswap8_internal
#define pswap16                          ordo_pswap16_internal
#define pswap32                          ordo_pswap32_internal
#define pswap64                          ordo_pswap64_internal
#define limit_constrain                  ordo_limit_constrain_internal
#define limit_check                      ordo_limit_check_internal
#define pad_check                        ordo_pad_check_internal
#define xor_buffer                       ordo_xor_buffer_internal
#define inc_buffer                       ordo_inc_buffer_internal

/*===----------------------------------------------------------------------===*/

/** @cond **/
#include "ordo/misc/endianness.h"
#include "ordo/common/error.h"
#include "ordo/internal/alg.h"
#include "ordo/internal/sys.h"

#include <stdlib.h>
#include <string.h>
/** @endcond **/

/*===----------------------------------------------------------------------===*/

#ifdef OPAQUE
    #undef OPAQUE
#endif

#if defined(__clang__)\
 || defined(__INTEL_COMPILER)\
 || defined(__GNUC__)\
 || defined(__MINGW32__)
    #define ALIGN(x) __attribute__((aligned(x)))
#elif defined(_MSC_VER)
    #define ALIGN(x) __declspec(align(x))
#endif

#if defined(__clang__) || defined(__INTEL_COMPILER)
    #define HOT_CODE __attribute__((hot))
    #define COLD_CODE __attribute__((cold))
#elif defined(__GNUC__) || defined(__MINGW32__)
    #define GCC_VERSION (__GNUC__ * 10000     \
                       + __GNUC_MINOR__ * 100 \
                       + __GNUC_PATCHLEVEL__)

    #if GCC_VERSION >= 40300 /* >= v4.3 support needed */
        #define HOT_CODE __attribute__((hot))
        #define COLD_CODE __attribute__((cold))
    #else
        #define HOT_CODE
        #define COLD_CODE
    #endif

    #undef GCC_VERSION
#elif defined(_MSC_VER)
    #define HOT_CODE
    #define COLD_CODE
#endif

/*===----------------------------------------------------------------------===*/

#endif
