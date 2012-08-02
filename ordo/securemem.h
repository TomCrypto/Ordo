#ifndef securemem_h
#define securemem_h

/**
 * @file securemem.h
 * Exposes the Secure Memory API.
 *
 * Header usage mode: External.
 *
 * @see securemem.c
 */

/* Standard includes. */
#include <stdlib.h>

/*! This function returns a pointer that is locked in physical memory.
 \param size The amount of memory to allocate, in bytes.
 \return Returns the allocated pointer on success, or 0 if the function fails.
 \remark Sometimes, operating systems can decide to page out rarely-accessed
 memory to the hard drive. However, once the memory is needed and is paged
 back in, its footprint on the hard drive is not erased. Thus, if cryptographic
 material is paged out in this way, it can be compromised by hard drive analysis
 even months after the event occurred. This function prevents this by instructing
 the operating system not to page out the allocated memory.
 \remark Note that this is a hint to the operating system, nothing more. Consult
 your operating system's implementation of virtual memory locking to know more. */
void* salloc(size_t size);

/*! This function sets memory as read-only. If this function succeeds, any attempt to
    write to the memory will incur an access violation, until the read-only restriction is lifted.
    Not generally useful but can always come in handy at some point.
 \param ptr The pointer to the memory to set as read-only.
 \param size The amount of memory, in bytes, to set as read-only. */
int sprotect(void* ptr, size_t size);

/*! This function frees a pointer, and securely erases the memory it points to.
 \param ptr An allocated pointer to free.
 \param size The amount of memory, in bytes, pointed to. */
void sfree(void* ptr, size_t size);

#endif
