/*===-- internal/implementation.h----------------------*- INTERNAL-*- H -*-===*/
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

#define rol16 rol16                                         ## _internal_ordo
#define ror16 ror16                                         ## _internal_ordo
#define rol32 rol32                                         ## _internal_ordo
#define ror32 ror32                                         ## _internal_ordo
#define rol64 rol64                                         ## _internal_ordo
#define ror64 ror64                                         ## _internal_ordo
#define smin smin                                           ## _internal_ordo
#define smax smax                                           ## _internal_ordo
#define pswap8 pswap8                                       ## _internal_ordo
#define pswap16 pswap16                                     ## _internal_ordo
#define pswap32 pswap32                                     ## _internal_ordo
#define pswap64 pswap64                                     ## _internal_ordo
#define pad_check pad_check                                 ## _internal_ordo
#define xor_buffer xor_buffer                               ## _internal_ordo
#define inc_buffer inc_buffer                               ## _internal_ordo
#define mem_alloc mem_alloc                                 ## _internal_ordo
#define mem_free mem_free                                   ## _internal_ordo
#define mem_erase mem_erase                                 ## _internal_ordo

/*===----------------------------------------------------------------------===*/

/** @cond **/
#include "ordo/misc/endianness.h"
#include "ordo/common/error.h"
#include "ordo/common/query.h"
#include "ordo/internal/alg.h"
#include "ordo/internal/sys.h"

#include <stdlib.h>
#include <string.h>
/** @endcond **/

/*===----------------------------------------------------------------------===*/

#if defined(__clang__) || defined(__GNUC__) || defined(__MINGW32__)
    #define ALIGN(x) __attribute__((aligned(x)))
#elif defined(_MSC_VER)
    #define ALIGN(x) __declspec(align(x))
#endif

#if defined(__clang__)
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
