#include <common/securemem.h>

/* Secure memory wipe. */
void swipe(void* ptr, size_t size)
{
    /* Overwrite each byte with zero. */
    if (!ptr) return;
    while (size--) *((uint8_t volatile*)ptr + size) = 0;
}

#if PLATFORM_LINUX

#include <sys/mman.h>

/* Secure memory allocation. */
void* salloc(size_t size)
{
    /* If we reach the locked memory limit, we must return zero, as salloc must return locked memory. This should not happen
     * in practice, as the limit is quite high and this should only be used for sensitive data such as cryptographic contexts
     * (which contain key material and plaintext in temporary buffers) which, usually, should not take up much memory. */
    void* ptr = malloc(size);
    return mlock(ptr, size) ? 0 : ptr;
}

/* Sets memory as read-only. */
int sprotect(void* ptr, size_t size)
{
    return mprotect(ptr, size, PROT_READ);
}

/* Secure memory deallocation. */
void sfree(void* ptr, size_t size)
{
    /* Ignore nil pointers. */
    if (ptr)
    {
        /* Wipe the memory. */
        swipe(ptr, size);

        /* Unlock the memory. */
        munlock(ptr, size);

        /* Free the memory. */
        free(ptr);
    }
}

#elif PLATFORM_WINDOWS

#include <Windows.h>

/* Secure memory allocation. */
void* salloc(size_t size)
{
    void* ptr = VirtualAlloc(0, size, MEM_COMMIT, PAGE_READWRITE);
    return VirtualLock(ptr, size) ? ptr : 0;
}

/* Sets memory as read-only. */
int sprotect(void* ptr, size_t size)
{
    DWORD old;
    return VirtualProtect(ptr, size, PAGE_READONLY, &old) ? 0 : -1;
}

/* Secure memory deallocation. */
void sfree(void* ptr, size_t size)
{
    /* Ignore nil pointers. */
    if (ptr)
    {
        /* Wipe the memory. */
        swipe(ptr, size);

        /* Unlock the memory. */
        VirtualUnlock(ptr, size);

        /* Free the memory. */
        VirtualFree(ptr, 0, MEM_RELEASE);
    }
}

#endif
