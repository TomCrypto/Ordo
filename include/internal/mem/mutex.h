#ifndef ORDO_MEM_MUTEX_H
#define ORDO_MEM_MUTEX_H

#include <stdlib.h>

/******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * @file mutex.h
 * @brief Memory allocator mutex module.
 * @internal
 *
 * This module provides the memory allocator with a single mutex to use
 * for thread safety.
 *
 * This module is for internal use only and must not be used outside the
 * library.
*/

/*! Initializes the mutex.
 @return Returns \c 0 on success, and any other value on error.
 @remarks This function will not be called again after it succeeds.
*/
int mutex_init(void);

/*! Acquires the mutex.
 @remarks This function must return only when the mutex has been acquired.
*/
void mutex_acquire(void);

/*! Releases the mutex.
 @remarks This function may assume the mutex is held by the calling thread.
*/
void mutex_release(void);

/*! Frees the mutex, releasing any memory used by the mutex.
 @remarks This function need not report an error even if it fails internally,
          as the host program will terminate shortly either way.
*/
void mutex_free(void);

#ifdef __cplusplus
}
#endif

#endif
