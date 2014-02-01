//===-- mem.c -----------------------------------------*- generic -*- C -*-===//

#include "ordo/internal/mem.h"

/// @cond
#include "ordo/internal/implementation.h"
/// @endcond

//===----------------------------------------------------------------------===//

static void *ordo_mem_alloc(size_t size)
{
    return malloc(size);
}

static void ordo_mem_free(void *ptr)
{
    free(ptr);
}

//===----------------------------------------------------------------------===//

static void *(*mem_alloc_f)(size_t, void *);
static void (*mem_free_f)(void *, void *);
static void *user_data;

void ordo_allocator(void *(*alloc)(size_t, void*),
                    void  (*free)(void *, void *),
                    void *data)
{
    if ((alloc != 0) && (free != 0))
    {
        mem_alloc_f = alloc;
        mem_free_f  = free;
        user_data = data;
    }
    else
    {
        mem_alloc_f = 0;
        mem_free_f = 0;
        user_data = 0;
    }
}

void *mem_alloc(size_t size)
{
    if (!mem_alloc_f) return ordo_mem_alloc(size);
    else return mem_alloc_f(size, user_data);
}

void mem_free(void *ptr)
{
    if (!mem_free_f) ordo_mem_free(ptr);
    else mem_free_f(ptr, user_data);
}

void mem_erase(void *ptr, size_t size)
{
    if (ptr)
    {
        // The "volatile" keyword forces the compiler to actually erase the
        // memory (otherwise it would optimize it out if it found that the
        // memory buffer wouldn't be used after mem_erase is called).
        while (size--) *((unsigned char volatile*)ptr + size) = 0;
    }
}
