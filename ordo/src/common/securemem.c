/**
 * @file securemem.c
 * Implements the Secure Memory API, which is a simple and lightweight cross-platform API designed to make secure memory management easy.
 *
 * \todo Implement other platforms.
 *
 * @see securemem.h
 */

#include <common/securemem.h>

#if PLATFORM_LINUX

#include <string.h>
#include <sys/mman.h>

/* Secure memory allocation. */
void* salloc(size_t size)
{
    void* ptr = malloc(size);
    if (mlock(ptr, size) != 0) return 0;
    else return ptr;
}

/* Sets memory as read-only. */
int sprotect(void* ptr, size_t size)
{
    return mprotect(ptr, size, PROT_READ);
}

/* Secure memory deallocation. */
void sfree(void* ptr, size_t size)
{
    memset(ptr, 0, size); // improve this later
    free(ptr);
}

#elif PLATFORM_WINDOWS

#include <Windows.h>

/* Secure memory allocation. */
void* salloc(size_t size)
{
    void* ptr = VirtualAlloc(0, size, MEM_COMMIT, PAGE_READWRITE);
    VirtualLock(ptr, size);
    return ptr;
}

/* Sets memory as read-only. */
int sprotect(void* ptr, size_t size)
{
    /* TIL VirtualProtect needs a dummy variable */
    DWORD old;
    VirtualProtect(ptr, size, PAGE_READONLY, &old);
    return 0; // change that later
}

/* Secure memory deallocation. */
void sfree(void* ptr, size_t size)
{
    /* improve this later */
    memset(ptr, 0, size);
    VirtualFree(ptr, 0, MEM_RELEASE);
}

#else
#error "Unknown platform."
#endif
