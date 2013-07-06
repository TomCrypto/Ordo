#include <internal/mem.h>

#include <internal/environment.h>

/******************************************************************************/

/* We use the same allocation strategy on all hardware for which memory is
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

/* The generic allocator uses a high-performance, fixed-size minipool, which is
 * sufficient for most uses. It does *not* fall back to an alternative pool.
 * This pool does not actually honor aligned memory requests, instead assuming
 * the library will never need stricter alignment than POOL_WORD bytes - which
 * should be the case for all the architectures using this implementation! */

/* Here ORDO_DEBUG implies ORDO_DEBUG_MEM, but the latter can be enabled
 * separately to test release builds by doing minimal memory tracking. */

/* Pool parameters. */
#define POOL_SIZE 1024
#define POOL_WORD 32
#define POOL_LEN (POOL_SIZE * POOL_WORD)


/* Make sure the pool starts on a correct boundary, for alignment. */
static unsigned char pool[POOL_LEN] __attribute__ ((aligned(POOL_WORD)));
static size_t distance[POOL_SIZE]; /* Used to mark blocks as used. */
static size_t usage = (size_t)-1; /* This stores total pool usage. */

/* In debug mode, the pool prints out some debug information to stdout. */
#ifdef ORDO_DEBUG_MEM
static size_t max_usage;
static size_t hit, miss;
#endif

#if defined(PLATFORM_POSIX)

#include <sys/mman.h>

static int mem_lock(void *ptr, size_t size)
{
    return mlock(ptr, size);
}

#elif defined(PLATFORM_WINDOWS)

#include <Windows.h>

static int mem_lock(void *ptr, size_t size)
{
    return !VirtualLock(ptr, size);
}

#endif

#ifdef ORDO_DEBUG_MEM

#include <stdlib.h>
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

    snprintf(buf, sizeof(buf) - 1, "Highest pool usage: %04u/%04u blocks "
                 "(%04.1f%% of %03u kB)",
           (int)max_usage, (int)POOL_SIZE,
           100 * (double)max_usage / POOL_SIZE,
           (int)(POOL_WORD * POOL_SIZE / 1024));

    strip_zeroes(buf);
    printf("| %s |\n", buf);

    snprintf(buf, sizeof(buf) - 1, "Total pool success: %05u blocks.",
             (int)hit);

    strip_zeroes(buf);
    printf("| %s                      |\n", buf);

    snprintf(buf, sizeof(buf) - 1, "Total pool failure: %05u blocks.",
             (int)miss);

    strip_zeroes(buf);
    printf("| %s                      |\n", buf);

    snprintf(buf, sizeof(buf) - 1, "Usage upon exit   : %05u blocks.",
             (int)usage);

    strip_zeroes(buf);
    printf("| %s                      |\n", buf);

    printf("+--------------------------------------------------------+\n");
}
#endif

void *mem_alloc(size_t size)
{
    /* Here we calculate the number of blocks needed to store "size" bytes, and
     * we consider a zero-byte allocation valid (it returns the very first pool
     * block but is obviously read-only by definiion. */
    size_t blocks = size / POOL_WORD + 1;
    if (!blocks) return pool;

    if (usage == (size_t)-1)
    {
        if (mem_lock(pool, POOL_LEN)) return 0;
        usage = 0;

        #ifdef ORDO_DEBUG_MEM
        atexit(report);
        #endif
    }

    if (usage + blocks < POOL_SIZE)
    {
        size_t t = 0;

        while (t + blocks < POOL_SIZE)
        {
            if (distance[t])
            {
                /* This block (and possibly more ahead) is used. Skip to the
                 * next block not belonging to this allocation. */
                t += distance[t];
            }
            else
            {
                size_t n;

                for (n = 1; n < blocks; ++n)
                    if (distance[t + n])
                        goto used_block;

                distance[t] = blocks;
                usage += blocks;

                #if ORDO_DEBUG_MEM
                /* In debug mode, record highest pool usage. */
                if (usage > max_usage) max_usage = usage;
                hit += blocks;
                #endif

                return pool + t * POOL_WORD;

used_block:
                ++t;
                continue;
            }
        }
    }

    #if ORDO_DEBUG_MEM
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
    if (!ptr) return;

    /* Here we assert that ptr actually points into the pool. If not, this is
     * unspecified behavior. This should never happen under normal usage. */
    if ((ptr >= (void*)pool) && (ptr < (void*)(pool + POOL_LEN)))
    {
        /* Recover the block's position using the two pointers. */
        size_t t = (size_t)((unsigned char*)ptr - pool) / POOL_WORD;
        mem_erase(ptr, distance[t] * POOL_WORD);
        usage -= distance[t];
        distance[t] = 0;
    }
}

#else

#error No Secure Memory implementation for this platform!

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

