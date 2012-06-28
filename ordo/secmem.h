#ifndef secmem_h
#define secmem_h

#include <stdlib.h>

/* Pass-through cross-platform header. */

void* salloc(size_t size);

void sfree(void* mem, size_t size);

#endif