#ifndef ORDO_SECUREMEM_H
#define ORDO_SECUREMEM_H

#include <stdlib.h>

/******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * @file secure_mem.h
 * @brief Secure memory module.
 *
 * Exposes the Secure Memory API, which is essentially a wrapper around
 * \c malloc and free, taking care of locking and securely erasing memory
 * for security-sensitive data. The library relies solely on this
 * implementation to allocate cryptographic contexts.
*/

/*! Allocates a pointer which is locked in physical memory.
 @param size The amount of memory to allocate, in bytes.
 @return Returns the allocated pointer on success, or 0 if the function fails.
         The function can fail if allocation fails (if the system is out of
         memory) or if locking fails (if the process has reached its locked
         memory limit). Neither of these conditions should arise under normal
         operation.
 @remark Sometimes, operating systems can decide to page out rarely-accessed
         memory to the hard drive. However, once the memory is needed and is
         paged back in, its footprint on the hard drive is not erased. Thus,
         if cryptographic material is paged out in this way, it can be
         compromised by hard drive analysis even months after the event
         occurred. This function prevents this by instructing the operating
         system not to page out the allocated memory. \n\n Note that this is
         a hint to the operating system, nothing more. Consult your operating
         system's implementation of virtual memory locking to know more. \n\n
 @remark Memory may be left uninitialized upon allocation.
*/
void* secure_alloc(size_t size);

/*! Marks memory as read-only.
 @param ptr The pointer to the memory to set as read-only.
 @param size The amount of memory, in bytes, to set as read-only.
 @return Returns 0 on success, and anything else on failure.
 @remark If this function succeeds, any attempt to write to the memory will
         incur an access violation until the read-only restriction is lifted.
*/
int secure_read_only(void* ptr, size_t size);

/*! Erases memory by overwriting it with zeroes.
 @param ptr The pointer to the memory to erase.
 @param size The amount of memory, in bytes, to erase.
*/
void secure_erase(void* ptr, size_t size);

/*! Frees a pointer, and securely erases the memory it points to.
 @param ptr An allocated pointer to memory to erase and free.
 @param size The amount of memory, in bytes, pointed to by ptr.
 @remark Passing nil to this function is valid and will do nothing.
*/
void secure_free(void* ptr, size_t size);

#ifdef __cplusplus
}
#endif

#endif
