#include <internal/mem/base.h>

#include <internal/environment.h>

/******************************************************************************/

/* Note - if your platform does not support memory locking, or if it somehow
 * doesn't make sense to do so, you can implement dummy functions for these. */

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
    VirtualUnlock(ptr, len);
}

#else

#error No memory allocator implementation for this platform!

#endif
