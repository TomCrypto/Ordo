#include <internal/mem/mutex.h>

#include <internal/environment.h>

/******************************************************************************/

/* Note: if your platform does not support threading, it is fine to implement
 * a dummy mutex interface in here which does absolutely nothing. */

/* For Windows & other POSIX systems, use pthreads. */

#if defined(PLATFORM_POSIX) || defined(PLATFORM_WINDOWS)

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
