#include "ordo/internal/mem/base.h"

#include "ordo/internal/environment.h"

/******************************************************************************/

/* Note - if your platform does not support memory locking, or if it somehow
 * doesn't make sense to do so, you can implement dummy functions here. */

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

#include <windows.h>

int mem_lock(void *ptr, size_t len)
{
    return !VirtualLock(ptr, len);
}

void mem_unlock(void *ptr, size_t len)
{
    VirtualUnlock(ptr, len);
}

#elif defined(__ARMEL__)

int mem_lock(void *ptr, size_t len)
{
    return 0;
}

void mem_unlock(void *ptr, size_t len)
{
    return;
}

#else

#error No memory allocator implementation for this platform!

#endif
