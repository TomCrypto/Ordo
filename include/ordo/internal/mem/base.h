#ifndef ORDO_MEM_BASE_H
#define ORDO_MEM_BASE_H

#include <stdlib.h>

/******************************************************************************/

/*!
 * @internal
 * @file base.h
 * @brief Memory allocator base module.
 *
 * This is an interface which abstracts away platform-dependent details in
 * order to provide standard functions for the memory allocator to use.
 *
 * This module is not to be used from outside the library, and is only
 * meaningful at compile-time.
*/

#ifdef __cplusplus
extern "C" {
#endif

/*! Locks a memory buffer into physical memory, ensuring it will not be
 *  paged out to less volatile storage.
 @param ptr The memory buffer to lock.
 @param len The length, in bytes, of the memory buffer.
 @return Returns \c 0 on success, and any other value on error.
 @remarks This function need not guarantee that the memory is locked (indeed,
          most operating systems do not guarantee such behavior), it just
          needs to advise the operating system towards this end.
 @remarks This function will not be called again once it succeeds.
*/
int mem_lock(void *ptr, size_t len);

/*! Unlocks a memory buffer, reversing the effect of \c mem_lock().
 @param ptr The memory buffer to unlock.
 @param len The length, in bytes, of the memory buffer.
 @remarks This function need not report an error even if it fails internally,
          as the host program will terminate shortly after either way.
*/
void mem_unlock(void *ptr, size_t len);

#ifdef __cplusplus
}
#endif

#endif
