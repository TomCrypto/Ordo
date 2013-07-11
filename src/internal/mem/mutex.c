#include <internal/mem/mutex.h>

#include <internal/environment.h>

/******************************************************************************/

/* Note: if your platform does not support threading, it is fine to implement
 * a dummy mutex implementation in here which does absolutely nothing. */

#if defined(PLATFORM_WINDOWS)

#include <windows.h>

/* We use a critical section because it's faster than a mutex under Windows
 * as it doesn't incur a kernel call (we don't care about inter-process). */
static CRITICAL_SECTION mutex;

int mutex_init(void)
{
    InitializeCriticalSection(&mutex);
    return 0;
}

void mutex_acquire(void)
{
    EnterCriticalSection(&mutex);
}

void mutex_release(void)
{
    LeaveCriticalSection(&mutex);
}

void mutex_free(void)
{
    DeleteCriticalSection(&mutex);
}

#elif defined(PLATFORM_POSIX)

#include <pthread.h>

static pthread_mutex_t mutex;

int mutex_init(void)
{
    return pthread_mutex_init(&mutex, 0);
}

void mutex_acquire(void)
{
    pthread_mutex_lock(&mutex);
}

void mutex_release(void)
{
    pthread_mutex_unlock(&mutex);
}

void mutex_free(void)
{
    pthread_mutex_destroy(&mutex);
}

#else

#error No mutex implementation for this platform!

#endif
