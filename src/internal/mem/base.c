#include <internal/mem/base.h>

#include <internal/environment.h>

/******************************************************************************/

#if defined(PLATFORM_POSIX)

#include <sys/mman.h>

int mem_lock(void *ptr, size_t len)
{
    return mlock(ptr, len);
}

void mem_unlock(void *ptr, size_t len)
{
    munlock(ptr, len);
}

#elif defined(PLATFORM_WINDOWS)

#include <Windows.h>

int mem_lock(void *ptr, size_t len)
{
    return !VirtualLock(ptr, len);
}

void mem_unlock(void *ptr, size_t len)
{
    return !VirtualUnlock(ptr, len);
}

#else

#error No Secure Memory base implementation for this platform!

#endif
