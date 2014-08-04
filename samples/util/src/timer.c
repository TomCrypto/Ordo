/*===-- timer.c -------------------------------------*- UTILITIES -*- C -*-===*/
/**
*** @file
*** @brief Utility
***
*** This is the implementation of the portable accurate timer routines, in the
*** timer.h header. It may change wildly depending on the underlying system.
**/
/*===----------------------------------------------------------------------===*/

#include "timer.h"

#if defined(_WIN32) /* On Windows, use system functions. */

#include <windows.h>
#include <signal.h>
#include <stdio.h>

static HANDLE timer_id;
static volatile sig_atomic_t timer_elapsed;

void CALLBACK timer_handler(void *aux, BOOLEAN unused)
{
    timer_elapsed = 1;
}

void timer_init(double seconds)
{
    timer_elapsed = 0;

    if (!CreateTimerQueueTimer(&timer_id, 0, timer_handler, 0,
                               (DWORD)(seconds * 1000), 0,
                               WT_EXECUTEONLYONCE))
    {
        printf("CreateTimerQueueTimer failed.\n");
        exit(EXIT_FAILURE);
    }
}


int timer_has_elapsed(void)
{
    return timer_elapsed;
}

double timer_now(void)
{
    static LARGE_INTEGER freq = {0};
    LARGE_INTEGER counter;

    if (!freq.QuadPart)
        QueryPerformanceFrequency(&freq);

    QueryPerformanceCounter(&counter);
    return (double)counter.QuadPart / freq.QuadPart;
}

void timer_free(void)
{
    DeleteTimerQueueTimer(0, timer_id, 0);
}

#elif defined(__OpenBSD__)

#include <time.h>

static double timer_delta, timer_start;

void timer_init(double seconds)
{
    timer_start = timer_now();
    timer_delta = seconds;
}

int timer_has_elapsed(void)
{
    return (timer_now() - timer_start) >= timer_delta;
}

double timer_now(void)
{
    struct timespec tv;
    clock_gettime(CLOCK_MONOTONIC, &tv);
    return tv.tv_sec + tv.tv_nsec / 1000000000.0;
}

void timer_free(void)
{
    return;
}

#elif defined(__APPLE__)

#include <sys/time.h>

static double timer_delta, timer_start;

void timer_init(double seconds)
{
    timer_start = timer_now();
    timer_delta = seconds;
}

int timer_has_elapsed(void)
{
    return (timer_now() - timer_start) >= timer_delta;
}

double timer_now(void)
{
    struct timeval tv;

    gettimeofday(&tv, 0);
    return tv.tv_sec + tv.tv_usec / 1000000.0;
}

void timer_free(void)
{
    return;
}

#else /* Assume we are on a POSIX 1993 compliant system. */

#define _POSIX_C_SOURCE 1993109L

#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

static timer_t timer_id;
static struct sigaction timer_old;
static volatile sig_atomic_t timer_elapsed;

static void timer_handler(int unused)
{
    timer_elapsed = 1;
}

void timer_init(double seconds)
{
    struct sigevent evp = {0};
    struct sigaction sig;
    struct itimerspec tm;

    tm.it_interval.tv_nsec = (long)(seconds - (long)seconds) * 1000000000;
    tm.it_interval.tv_sec = (time_t)seconds;
    tm.it_value = tm.it_interval;
    timer_elapsed = 0;

    sig.sa_handler = timer_handler;
    sigemptyset(&sig.sa_mask);
    sig.sa_flags = 0;

    evp.sigev_value.sival_ptr = &timer_id;
    evp.sigev_notify = SIGEV_SIGNAL;
    evp.sigev_signo = SIGALRM;

    if (timer_create(CLOCK_MONOTONIC, &evp, &timer_id))
    {
        perror("timer_create");
        exit(EXIT_FAILURE);
    }

    if (timer_settime(timer_id, 0, &tm, 0))
    {
        perror("timer_settime");
        exit(EXIT_FAILURE);
    }

    if (sigaction(SIGALRM, &sig, &timer_old))
    {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }
}

int timer_has_elapsed(void)
{
    return timer_elapsed;
}

double timer_now(void)
{
    struct timespec tv;
    clock_gettime(CLOCK_MONOTONIC, &tv);
    return tv.tv_sec + tv.tv_nsec / 1000000000.0;
}

void timer_free(void)
{
    sigaction(SIGALRM, &timer_old, 0);
    timer_delete(timer_id);
}

#endif
