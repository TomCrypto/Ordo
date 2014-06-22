/*===-- internal/sys.h -------------------------------*- INTERNAL -*- H -*-===*/
/**
*** @file
*** @internal
*** @brief \b Internal, Utility
***
*** This header provides system-dependent functionality and is internal to the
*** library. It probably shouldn't ever be used from outside the library.
***
*** See \c alg.h about internal headers.
**/
/*===----------------------------------------------------------------------===*/

#ifndef ORDO_SYS_H
#define ORDO_SYS_H

/** @cond **/
#include "ordo/common/interface.h"
/** @endcond **/

#ifdef __cplusplus
extern "C" {
#endif

/*===----------------------------------------------------------------------===*/

#if !(defined(ORDO_INTERNAL_ACCESS) && defined(ORDO_STATIC_LIB))
    #if !(defined(BUILDING_ORDO) || defined(BUILDING_ordo))
        #error "This header is internal to the Ordo library."
    #endif
#endif

/*===----------------------------------------------------------------------===*/

#ifdef __cplusplus
}
#endif

#endif
