#ifndef ORDO_MEM_H
#define ORDO_MEM_H

#include <stdlib.h>

/******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * @file mem.h
 * @brief Memory allocator module.
 * @internal
 *
 * Contains the library's memory allocator/manager. The library relies solely
 * on this interface to allocate cryptographic contexts. Memory allocated by
 * this module is locked in physical memory and will be automatically erased
 * upon deallocation. This module also provides memory alignment facilities,
 * and guarantees thread safety of allocation and deallocation functions.
 *
 * This module is for internal use only and must not be used outside the
 * library.
*/

/*! Allocates a memory buffer.
 @param size The amount of memory to allocate, in bytes.
 @return Returns a pointer to the allocated memory buffer on success, or nil
         if the function fails.
 @remarks This function will fail if and only if there is not enough memory
          left to honor the allocation request. This can happen if the heap
          is badly fragmented (should not happen as the library does not
          allocate a lot of data) or if the process's memory locking quota
          is reached (should not happen under normal operation).
 @remarks Memory may be left uninitialized upon allocation.
 @remarks This function is thread-safe.
*/
void* mem_alloc(size_t size);

/*! Deallocates a memory buffer.
 @param ptr A memory buffer to free.
 @remarks Passing nil to this function is valid and will do nothing.
 @remarks The memory buffer must have been allocated with either
          \c mem_alloc() or \c mem_aligned().
 @remarks The memory buffer will be overwritten with zeroes, ensuring no
          sensitive data lingers in memory.
 @remarks This function is thread-safe.
*/
void mem_free(void *ptr);

/*! Overwrites a memory buffer with zeroes.
 @param ptr The memory buffer to overwrite.
 @param size The number of bytes to overwrite.
*/
void mem_erase(void *ptr, size_t size);

/*! Initializes the memory allocator.
 @return Returns 0 on success, and any other value on error.
 @remarks This is called by \c ordo_init().
 @remarks Must be called before any other \c mem_* function is called.
 @remarks Once the function has succeeded, it becomes idempotent.
 @remarks The memory allocator will be automatically destroyed when
          the host program terminates.
*/
int mem_init(void);

#ifdef __cplusplus
}
#endif

#endif
