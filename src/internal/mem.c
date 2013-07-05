#include <internal/mem.h>

#include <internal/environment.h>

/******************************************************************************/

/* We use the same allocation strategy on all hardware for which efficiency is
 * not a concern, abstracting away any platform-specific system calls. */
#if ((defined(PLATFORM_LINUX)) \
 ||  (defined(PLATFORM_NETBSD)) \
 ||  (defined(PLATFORM_OPENBSD)) \
 ||  (defined(PLATFORM_FREEBSD)) \
 ||  (defined(PLATFORM_WINDOWS))) \
 && (defined(__x86_64__) || defined(__i386__))
    #define GENERIC_ALLOCATOR
#endif

#ifdef GENERIC_ALLOCATOR

#include <stdlib.h>

/* The generic allocator uses a high-performance, fixed-size minipool, which is
 * sufficient for most uses. It does *not* fall back to an alternative pool. */
#define POOL_SIZE 1024
#define POOL_WORD 32

/* This pool does not actually honor aligned memory requests, instead assuming
 * the library will never need stricter alignment than POOL_WORD bytes - which
 * should be the case for all the architectures using this implementation! */
static unsigned char pool[(POOL_SIZE + 1) * POOL_WORD];
static size_t distance[POOL_SIZE]; /* Range probing. */
static size_t usage = (size_t)-1;
static size_t offset;

#ifdef ORDO_DEBUG
static size_t max_usage;
static size_t hit, miss;
#endif

#if PLATFORM_LINUX || PLATFORM_NETBSD || PLATFORM_OPENBSD || PLATFORM_FREEBSD

#include <sys/mman.h>

static int mem_lock(void *ptr, size_t size)
{
    return mlock(ptr, size);
}

#elif PLATFORM_WINDOWS

#include <Windows.h>

static int mem_lock(void *ptr, size_t size)
{
    return !VirtualLock(ptr, size);
}

#endif

#ifdef ORDO_DEBUG

#include <string.h>
#include <stdio.h>

/* Used to strip leading zeroes for presentation. */
static void strip_zeroes(char *str)
{
    size_t t, len = strlen(str);
    for (t = 1; t < len - 1; ++t)
    {
        if ((str[t] == '0')
        && ((!isdigit(str[t - 1]))
        && (isdigit(str[t + 1])))) str[t] = ' ';
    }
}

static void report()
{
    char buf[64]; /* Guaranteed to be large enough.. sigh.. */

    printf("\n");
    printf("+--------------------------------------------------------+\n");
    printf("| Reported Memory Statistics  (collected during runtime) |\n");
    printf("| ****************************************************** |\n");

    snprintf(buf, 64, "Highest pool usage: %04u/%04u blocks "
                 "(%04.1f%% of %03u kB)",
           (int)max_usage, (int)POOL_SIZE,
           100 * (double)max_usage / POOL_SIZE,
           (int)(POOL_WORD * POOL_SIZE / 1024));

    strip_zeroes(buf);
    printf("| %s |\n", buf);

    snprintf(buf, 64, "Total pool success: %05u blocks.", (int)hit);
    strip_zeroes(buf);
    printf("| %s                      |\n", buf);

    snprintf(buf, 64, "Total pool failure: %05u blocks.", (int)miss);
    strip_zeroes(buf);
    printf("| %s                      |\n", buf);

    snprintf(buf, 64, "Usage upon exit   : %05u blocks.", (int)usage);
    strip_zeroes(buf);
    printf("| %s                      |\n", buf);

    printf("+--------------------------------------------------------+\n");
}
#endif

void *mem_alloc(size_t size)
{
    size_t blocks = size / POOL_WORD + 1, t = 0;
    if (!blocks) return pool;

    if (usage == (size_t)-1)
    {
        /* Acquire a pool offset of the alignment boundary we require. */
        while (((size_t)(pool + offset) & (POOL_WORD - 1)) != 0) ++offset;
        
        if (mem_lock(pool, sizeof(pool))) return 0;

        usage = 0;

        #ifdef ORDO_DEBUG
        atexit(report);
        #endif
    }

    while ((usage + blocks <= POOL_SIZE) || (offset + t + blocks < POOL_SIZE))
    {
        if (distance[t]) t += distance[t];
        else
        {
            size_t n;

            for (n = 1; n < blocks; ++n)
                if (distance[t + n]) goto used;

            distance[t] = blocks;
            usage += blocks;

            #if ORDO_DEBUG
            if (usage > max_usage) max_usage = usage;
            hit += blocks;
            #endif

            return &pool[offset + t * POOL_WORD];

used:
            ++t;
            continue;
        }
    }

    #if ORDO_DEBUG
    miss += blocks;
    #endif

    return 0;
}

void *mem_aligned(size_t size, size_t alignment)
{
    /* Disallow non-power of two alignments, as well as > POOL_WORD. */
    if ((alignment & (alignment - 1)) != 0) return 0;
    if (alignment > POOL_WORD) return 0;
    return mem_alloc(size);
}

void mem_free(void *ptr)
{
    unsigned char *cmp = pool + offset;
    if (!ptr) return;

    /* This is technically unspecified behaviour, but it will
     * work on the platforms on which this code is executed. */
    if (((unsigned char*)ptr >= cmp)
     && ((unsigned char*)ptr < cmp + POOL_WORD * POOL_SIZE))
    {
        size_t t = (size_t)((unsigned char*)ptr - cmp) / POOL_WORD;
        mem_erase(ptr, distance[t] * POOL_WORD);
        usage -= distance[t];
        distance[t] = 0;
    }
}

#else

#error "No Secure Memory implementation for this platform!"

#endif

void mem_erase(void *ptr, size_t size)
{
    if (ptr)
    {
        /* The "volatile" keyword forces the compiler to actually erase the
         * memory (otherwise it would optimize it out if it found that the
         * memory buffer wouldn't be used after mem_erase is called). */
        while (size--) *((unsigned char volatile*)ptr + size) = 0;
    }
}

