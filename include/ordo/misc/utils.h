/*===-- misc/utils.h =----------------------------------*- PUBLIC -*- H -*-===*/
/**
*** @file
*** @brief Utility
***
*** This header contains utility functions that are of use to developers which
*** will use the library, for instance, constant-time comparisons and so on.
**/
/*===----------------------------------------------------------------------===*/

#ifndef ORDO_UTILS_H
#define ORDO_UTILS_H

/** @cond **/
#include "ordo/common/interface.h"
/** @endcond **/

#ifdef __cplusplus
extern "C" {
#endif

#define ctcmp                            ordo_ctcmp

/*===----------------------------------------------------------------------===*/

/** Performs a constant-time comparison between two buffers.
***
*** @param [in]     x              The 1st buffer.
*** @param [in]     y              The 2nd buffer.
*** @param [in]     len            Length in bytes.
***
*** @returns Returns a positive value if the buffers match, \c 0 otherwise.
***
*** @warning You cannot use this function to determine if x < y.
**/
ORDO_PUBLIC
int ctcmp(const void *x, const void *y, size_t len);

/*===----------------------------------------------------------------------===*/

#ifdef __cplusplus
}
#endif

#endif
