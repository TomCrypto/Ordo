#include "secmem.h"

#if defined __linux__

#include <stdlib.h>

/* Secure memory allocation. */
void* salloc(size_t size)
{
	void* ptr = malloc(size);
	mlock(ptr, size);
	return ptr;
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

/* Secure memory deallocation. */
void sfree(void* ptr, size_t size)
{
	memset(ptr, 0, size); // improve this later
	VirtualFree(ptr, 0, MEM_RELEASE);
}

#else
#error "Unknown platform."
#endif