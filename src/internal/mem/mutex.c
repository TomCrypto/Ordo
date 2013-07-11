#include <internal/mem/mutex.h>

#include <internal/environment.h>

/******************************************************************************/

/* Note: if your platform does not support threading, it is fine to implement
 * a dummy mutex implementation in here which does absolutely nothing. */

#if defined(PLATFORM_WINDOWS)

#include <windows.h>

static HANDLE mutex;

int mutex_init(void)
{
    return ((mutex = CreateMutex(0, 0, 0)) == 0);
}

void mutex_acquire(void)
{
    WaitForSingleObject(mutex, INFINITE);
}

void mutex_release(void)
{
    ReleaseMutex(mutex);
}

void mutex_free(void)
{
    CloseHandle(mutex);
}

#elif defined(PLATFORM_BSD)

#include <sys/param.h>
#include <sys/lock.h>
#include <sys/mutex.h>

static struct mtx mutex;

int mutex_init(void)
{
    mtx_init(&mutex, "ordo_mem", 0, MTX_DEF);
}

void mutex_acquire(void)
{
    mtx_lock(&mutex);
}

void mutex_release(void)
{
    mtx_unlock(&mutex);
}

void mutex_free(void)
{
    mtx_destroy(&mutex);
}

#elif defined(PLATFORM_LINUX)

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
