#ifndef SECUREMEM_H
#define SECUREMEM_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file securemem.h
 * \brief Secure memory API.
 *
 * Exposes the Secure Memory API, which is essentially a wrapper around malloc and free, taking care of locking and
 * securely erasing memory for security-sensitive data. The library relies solely on this implementation to allocate
 * cryptographic contexts.
 *
 * @see securemem.c
 */

/* Library includes. */
#include "ordotypes.h"

/*! This function returns a pointer that is locked in physical memory.
 \param size The amount of memory to allocate, in bytes.
 \return Returns the allocated pointer on success, or 0 if the function fails. The function can fail if allocation
 fails (if the system is out of memory) or if locking fails (if the process has reached its locked memory limit).
 Neither of these conditions should arise under normal operation.
 \remark Sometimes, operating systems can decide to page out rarely-accessed memory to the hard drive. However, once
 the memory is needed and is paged back in, its footprint on the hard drive is not erased. Thus, if cryptographic
 material is paged out in this way, it can be compromised by hard drive analysis even months after the event occurred.
 This function prevents this by instructing the operating system not to page out the allocated memory. \n\n
 Note that this is a hint to the operating system, nothing more. Consult your operating system's implementation
 of virtual memory locking to know more. \n\n
 Memory may be left uninitialized upon allocation. */
void* salloc(size_t size);

/*! This function sets memory as read-only. If this function succeeds, any attempt to write to the memory will incur
 * an access violation, until the read-only restriction is lifted.
 \param ptr The pointer to the memory to set as read-only.
 \param size The amount of memory, in bytes, to set as read-only.
 \return Returns 0 on success, and anything else on failure. */
int sprotect(void* ptr, size_t size);

/*! This function wipes memory by overwriting it with zeroes.
 \param ptr The pointer to the memory to wipe.
 \param size The amount of memory, in bytes, to wipe. */
void swipe(void* ptr, size_t size);

/*! This function frees a pointer, and securely erases the memory it points to.
 \param ptr An allocated pointer to memory to erase and free.
 \param size The amount of memory, in bytes, pointed to by ptr.
 \remark Passing zero to this function is valid and will do nothing. */
void sfree(void* ptr, size_t size);

#ifdef __cplusplus
}
#endif

#endif
