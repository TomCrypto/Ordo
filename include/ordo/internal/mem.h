#ifndef ORDO_MEM_H
#define ORDO_MEM_H

/*! @cond */
#include <stdlib.h>
/*! @endcond */

#include "ordo/internal/api.h"

/******************************************************************************/

/*!
 * @internal
 * @file mem.h
 * @brief Memory allocator module.
 *
 * Contains the library's memory allocator/manager. The library relies solely
 * on this interface to allocate cryptographic contexts. Memory allocated by
 * this module is locked in physical memory and will be automatically erased
 * upon deallocation. This module also provides memory alignment facilities,
 * and guarantees thread safety of allocation and deallocation functions.
 *
 * This module is not to be used from outside the library, with the exception
 * of the \c mem_allocator() function if you wish to replace the default
 * memory allocator with your own.
*/

#ifdef __cplusplus
extern "C" {
#endif

typedef void *(ORDO_CALLCONV *MEM_ALLOC)(size_t);
typedef void  (ORDO_CALLCONV *MEM_FREE)(void*);

/*! Allocates a memory buffer.
 *  @param size The amount of memory to allocate, in bytes.
 *  @return Returns a pointer to the allocated memory buffer on success, or nil
 *          if the function fails.
 *  @remarks This function will fail if and only if there is not enough memory
 *           left to honor the allocation request.
 *  @remarks Memory may be left uninitialized upon allocation.
 *  @remarks Memory returned by this function is guaranteed to be aligned for
 *           all possible uses by the library (e.g. on a generic x86 processor,
 *           it will be aligned to a 32-byte boundary).
 *  @remarks This function is thread-safe.
*/
ORDO_API void * ORDO_CALLCONV
mem_alloc(size_t size);

/*! Deallocates a memory buffer.
 *  @param ptr A memory buffer to free.
 *  @remarks Passing nil to this function is valid and will do nothing.
 *  @remarks The memory buffer must have been allocated with \c mem_alloc().
 *  @remarks The memory buffer will be overwritten with zeroes, ensuring no
 *           sensitive data lingers in memory.
 *  @remarks This function is thread-safe.
*/
ORDO_API void ORDO_CALLCONV
mem_free(void *ptr);

/*! Overwrites a memory buffer with zeroes.
 *  @param ptr The memory buffer to overwrite.
 *  @param size The number of bytes to overwrite.
*/
ORDO_API void ORDO_CALLCONV
mem_erase(void *ptr, size_t size);

/*! Initializes the default memory allocator.
 *  @return Returns 0 on success, and any other value on error.
 *  @remarks This function is called by \c ordo_init().
 *  @remarks Must be called before any other \c mem_* function is called,
 *           unless the default allocator was overriden.
 *  @remarks Will do nothing if it is called after it succeeds.
 *  @remarks The default memory allocator will be automatically destroyed when
             the host program terminates (this will not interfere with custom
             allocators).
*/
ORDO_API int ORDO_CALLCONV
mem_init(void);

/*! Replaces the default memory allocator with a custom one.
 *  @param alloc The allocation function.
 *  @param free The deallocation function.
 *  @remarks Once this function has returned, all memory allocations done by
 *           the library will go through these functions.
 *  @remarks Do \b not use this function while the library currently has active
 *           allocations, for obvious reasons. As a result, this should only be
 *           used at the start of the program, or at a point where you know the
 *           library to not be using any allocated memory.
 *  @remarks Calling this function with both arguments nil restores the default
 *           memory allocator, in the state it was when it was replaced. You
 *           need not call \c mem_init() again if you had already done so.
 *  @remarks Any guarantees made by the \c mem_alloc() function do not apply
 *           when using a custom allocator (in other words, you are on your
 *           own).
*/
ORDO_API void ORDO_CALLCONV
mem_allocator(MEM_ALLOC alloc, MEM_FREE free);

#ifdef __cplusplus
}
#endif

#endif
