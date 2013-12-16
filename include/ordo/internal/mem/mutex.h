#ifndef ORDO_MEM_MUTEX_H
#define ORDO_MEM_MUTEX_H

#if !defined(ORDO_DISABLE_POOL)

#include "ordo/internal/api.h"

/******************************************************************************/

/*!
 * @internal
 * @file mutex.h
 * @brief Memory allocator mutex module.
 *
 * This module provides the memory allocator with a single mutex to use
 * for thread safety.
 *
 * This module is not to be used from outside the library, and is only
 * meaningful at compile-time.
*/

#ifdef __cplusplus
extern "C" {
#endif

/*! Initializes the mutex.
 @return Returns \c 0 on success, and any other value on error.
 @remarks This function will not be called again after it succeeds.
*/
ORDO_INTERNAL int ORDO_CALLCONV
mutex_init(void);

/*! Acquires the mutex.
 @remarks This function must return only when the mutex has been acquired.
*/
ORDO_INTERNAL void ORDO_CALLCONV
mutex_acquire(void);

/*! Releases the mutex.
 @remarks This function may assume the mutex is held by the calling thread.
*/
ORDO_INTERNAL void ORDO_CALLCONV
mutex_release(void);

/*! Frees the mutex, releasing any memory used by the mutex.
 @remarks This function need not report an error even if it fails internally,
          as the host program will terminate shortly either way.
*/
ORDO_INTERNAL void ORDO_CALLCONV
mutex_free(void);

#ifdef __cplusplus
}
#endif

#endif

#endif
