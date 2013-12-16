#include "ordo/internal/mem.h"

#if !defined(ORDO_DISABLE_POOL)

#include "ordo/internal/environment.h"

#include "ordo/internal/mem/base.h"
#include "ordo/internal/mem/mutex.h"
#include "ordo/internal/mem/params.h"

/******************************************************************************/

/* The generic allocator uses a high-performance, fixed-size slab allocator, *
 * sufficient for most uses. It does *not* fall back to an alternative pool. */
static ORDO_ALIGN(POOL_WORD) unsigned char pool[POOL_LEN];
static size_t allocated[POOL_SIZE];
static size_t usage;

/* The mem_init() function uses a state machine to ensure no operation that
 * has already been successfully carried out is done again - see following:
 * M_DEFAULT: nothing has been done, the memory manager is not ready.
 * M_LOCKED: the memory pool has been locked into memory.
 * M_MUTEX: the mutex has been initialized.
 * M_READY: the memory manager is ready.
*/
enum MEM_STATE { M_DEFAULT, M_LOCKED, M_MUTEX, M_READY };
static enum MEM_STATE state;

static void mem_final(void)
{
    mem_unlock(pool, POOL_LEN);
    mutex_free();
}

int ORDO_CALLCONV
mem_init(void)
{
    if (state != M_READY)
    {
        if (state < M_LOCKED)
        {
            int err = mem_lock(pool, POOL_LEN);
            if (err) return err;
            state = M_LOCKED;
        }

        if (state < M_MUTEX)
        {
            int err = mutex_init();
            if (err) return err;
            state = M_MUTEX;
        }

        if (state < M_READY)
        {
            int err = atexit(mem_final);
            if (err) return err;
            state = M_READY;
        }
    }

    return 0;
}

static void * ORDO_CALLCONV
ordo_mem_alloc(size_t size)
{
    if (state == M_READY)
    {
        size_t blocks = 1 + (size - 1) / POOL_WORD;
        if (size == 0) return pool;

        mutex_acquire();

        if (usage + blocks <= POOL_SIZE)
        {
            size_t n, t = 0;

            while (t + blocks <= POOL_SIZE)
            {
                for (n = 0; n < blocks; ++n)
                    if (allocated[t + n])
                    {
                        t += n + allocated[t + n];
                        goto retry;
                    }

                allocated[t] = blocks;
                
                usage += blocks;
                mutex_release();
                
                return pool + t * POOL_WORD;
retry:
                continue;
            }
        }

        mutex_release();
    }

    return 0;
}

static void ORDO_CALLCONV
ordo_mem_free(void *ptr)
{
    if ((!ptr) || (state != M_READY)) return;

    /* Here we assert that ptr actually points into the pool. If not, this is
     * unspecified behavior. This should never happen under normal usage. */
    if ((ptr >= (void*)pool) && (ptr < (void*)(pool + POOL_LEN)))
    {
        /* Retrieve the block position by using the two pointers. */
        size_t t = (size_t)((unsigned char*)ptr - pool) / POOL_WORD;
        mem_erase(ptr, allocated[t] * POOL_WORD);

        /* We need a lock here because another thread might be trying to
         * allocate some memory - what if it happens to hit this block?! */
        mutex_acquire();
        usage -= allocated[t];
        allocated[t] = 0;
        mutex_release();
    }
}

/******************************************************************************/

static MEM_ALLOC mem_alloc_f = ordo_mem_alloc;
static MEM_FREE mem_free_f   = ordo_mem_free;

void ORDO_CALLCONV
mem_allocator(MEM_ALLOC alloc, MEM_FREE free)
{
    int revert = ((alloc == 0) && (free == 0));

    mem_alloc_f = (revert ? ordo_mem_alloc : alloc);
    mem_free_f  = (revert ? ordo_mem_free  : free);
}

#else

int ORDO_CALLCONV
mem_init(void)
{
    return 0;
}

static MEM_ALLOC mem_alloc_f = 0;
static MEM_FREE mem_free_f   = 0;

void mem_allocator(MEM_ALLOC alloc, MEM_FREE free)
{
    mem_alloc_f = alloc;
    mem_free_f  = free;
}

#endif

void * ORDO_CALLCONV
mem_alloc(size_t size)
{
    return mem_alloc_f(size);
}

void ORDO_CALLCONV
mem_free(void *ptr)
{
    mem_free_f(ptr);
}

void ORDO_CALLCONV
mem_erase(void *ptr, size_t size)
{
    if (ptr)
    {
        /* The "volatile" keyword forces the compiler to actually erase the
         * memory (otherwise it would optimize it out if it found that the
         * memory buffer wouldn't be used after mem_erase is called). */
        while (size--) *((unsigned char volatile*)ptr + size) = 0;
    }
}
