//===-- internal/mem.h --------------------------------*- INTERNAL-*- H -*-===//
///
/// @file
/// @internal
/// @brief \b Internal, Utility
///
/// Contains the  library's memory manager. The library  relies solely on this
/// on this interface to allocate  cryptographic  contexts. This header should
/// not be used outside the library, but this is not  enforced beyond the fact
/// that the functions are not exported - you can  include this header and use
/// the memory manager if you are linking statically (but not dynamically).
///
/// If you are just trying to  change the allocator used, this is now provided
/// elsewhere, in the \c ordo.h header - see \c ordo_allocator().
///
//===----------------------------------------------------------------------===//

#ifndef ORDO_MEM_H
#define ORDO_MEM_H

/// @cond
#include "ordo/common/interface.h"
/// @endcond

#ifdef __cplusplus
extern "C" {
#endif

//===----------------------------------------------------------------------===//

/// Allocates a memory buffer.
///
/// @param [in]     size           The amount of memory required, in bytes.
///
/// @returns A  pointer to  the  allocated  memory on  success, or \c 0 if the
///          function fails to allocate the requested amount of memory.
///
/// @remarks Memory may be left uninitialized upon allocation.
///
/// @remarks Memory returned by the function is expected to be aligned for all
///          possible uses by the library.
///
/// @remarks This function is thread-safe.
ORDO_HIDDEN
void *mem_alloc(size_t size);

/// Deallocates a memory buffer.
///
/// @param [in]     ptr            A memory buffer to free.
///
/// @remarks Passing \c 0 to this function is valid and will do nothing.
///
/// @remarks The memory buffer must have been allocated with \c mem_alloc().
///
/// @remarks This function is thread-safe.
ORDO_HIDDEN
void mem_free(void *ptr);

/// Overwrites a memory buffer with zeroes.
///
/// @param [in,out] ptr            The memory buffer to overwrite.
/// @param [in]     size           The number of bytes to overwrite.
ORDO_HIDDEN
void mem_erase(void *ptr, size_t size);

/// Initializes the default memory allocator.
///
/// @return 0 on success, and any  other (not necessarily meaningful) value on
///         error (the error codes returned may be system-dependent).
///
/// @remarks This function is called by \c ordo_init().
///
/// @remarks This must be called before any other \c mem_* function is called,
///          unless the default allocator was overriden (\c ordo_allocator()).
///
/// @remarks It is safe to call this function multiples times after success.
ORDO_HIDDEN
int mem_init(void);

//===----------------------------------------------------------------------===//

#ifdef __cplusplus
}
#endif

#endif
