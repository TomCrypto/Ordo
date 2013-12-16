#include "ordo/internal/mem/base.h"

#if !defined(ORDO_DISABLE_POOL)

#include "ordo/internal/environment.h"

/******************************************************************************/

/* Note - if your platform does not support memory locking, or if it somehow
 * doesn't make sense to do so, you can implement dummy functions here. */

#if defined(PLATFORM_POSIX)

#include <sys/mman.h>

int ORDO_CALLCONV
mem_lock(void *ptr, size_t len)
{
    return mlock(ptr, len);
}

void ORDO_CALLCONV
mem_unlock(void *ptr, size_t len)
{
    munlock(ptr, len);
}

#elif defined(PLATFORM_WINDOWS)

#include <windows.h>

int ORDO_CALLCONV
mem_lock(void *ptr, size_t len)
{
    return !VirtualLock(ptr, len);
}

void ORDO_CALLCONV
mem_unlock(void *ptr, size_t len)
{
    VirtualUnlock(ptr, len);
}

#else

#error No memory pool base implementation for this platform!

#endif

#endif
