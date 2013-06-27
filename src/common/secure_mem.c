#include <common/secure_mem.h>

#include <internal/environment.h>

/******************************************************************************/

/* This is hopefully cross-platform. */
void secure_erase(void* ptr, size_t size)
{
    if (ptr)
    {
        /* The "volatile" keyword forces the compiler to actually erase the
         * memory (otherwise it would optimize it out if it found that the
         * memory buffer would never be used after secure_erase is called). */
        while (size--) *((unsigned char volatile*)ptr + size) = 0;
    }
}

#if PLATFORM_LINUX

#include <sys/mman.h>

void* secure_alloc(size_t size)
{
    /* If we reach the locked memory limit, we must return zero, as
     * secure_alloc must return locked memory. This should not happen
     * in practice, as the limit is quite high and this should only
     * be used for sensitive data such as cryptographic contexts
     * (which contain key material and plaintext in temporary buffers)
     * which, usually, should not take up much memory. */
    void* ptr = malloc(size);
    if (!mlock(ptr, size)) return ptr;
    free(ptr);
    return 0;
}

int secure_read_only(void* ptr, size_t size)
{
    return mprotect(ptr, size, PROT_READ);
}

void secure_free(void* ptr, size_t size)
{
    if (ptr)
    {
        secure_erase(ptr, size);
        munlock(ptr, size);
        free(ptr);
    }
}

#elif PLATFORM_WINDOWS

#include <Windows.h>

void* secure_alloc(size_t size)
{
    void* ptr = VirtualAlloc(0, size, MEM_COMMIT, PAGE_READWRITE);
    return VirtualLock(ptr, size) ? ptr : 0;
}

int secure_read_only(void* ptr, size_t size)
{
    DWORD old;
    return VirtualProtect(ptr, size, PAGE_READONLY, &old) ? 0 : -1;
}

void secure_free(void* ptr, size_t size)
{
    if (ptr)
    {
        secure_erase(ptr, size);
        VirtualUnlock(ptr, size);
        VirtualFree(ptr, 0, MEM_RELEASE);
    }
}

#else
#error "No Secure Memory implementation for this platform!"
#endif
