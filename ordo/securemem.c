/**
 * @file SecureMem.c
 * Implements the Secure Memory API, which is a simple and lightweight cross-platform API designed to make secure memory management easy.
 *
 * @see SecureMem.h
 */

#include "securemem.h"

#if defined __linux__

/* Secure memory allocation. */
void* salloc(size_t size)
{
	void* ptr = malloc(size);
	mlock(ptr, size);
	return ptr;
}

/* Sets memory as read-only. */
void sprotect(void* ptr, size_t size)
{
	mprotect(ptr, size, PROT_READ);
}

/* Secure memory deallocation. */
void sfree(void* ptr, size_t size)
{
	memset(ptr, 0, size); // improve this later
	free(ptr);
}

#elif defined _WIN32 || defined _WIN64

#include <Windows.h>

/* Secure memory allocation. */
void* salloc(size_t size)
{
	void* ptr = VirtualAlloc(0, size, MEM_COMMIT, PAGE_READWRITE);
	VirtualLock(ptr, size);
	return ptr;
}

/* Sets memory as read-only. */
void sprotect(void* ptr, size_t size)
{
	DWORD old; // TIL VirtualProtect needs a dummy variable
	VirtualProtect(ptr, size, PAGE_READONLY, &old);
}

/* Secure memory deallocation. */
void sfree(void* ptr, size_t size)
{
	memset(ptr, 0, size); // improve this later
	VirtualFree(ptr, 0, MEM_RELEASE);
}

#else
#error "Unknown platform."
#endif
