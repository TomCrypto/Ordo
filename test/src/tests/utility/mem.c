#include "tests/utility/mem.h"

#include "ordo/internal/mem.h"

int test_mem(char *output, size_t maxlen, FILE *ext)
{
    #if defined(ORDO_NO_POOL)
    
    if (ext) fprintf(ext, "[*] Pool disabled in this build, setting library "
                          "allocator to a valid allocator for the remaining "
                          "test cases.\n\n");
    
    ordo_allocator(malloc, free);
    
    if (ext) fprintf(ext, "[+] Allocator set.\n\n");
    
    #endif

    #if defined(ORDO_STATIC_LIB)

    void *ptr;

    if (ext) fprintf(ext, "[*] Testing memory allocator.\n\n");

    ptr = mem_alloc(0);

    if (!ptr)
    {
        if (ext) fprintf(ext, "[!] 'mem_alloc' should accept zero-byte "
                              "allocations, this is an error.\n\n");
        fail("'mem_alloc' rejects zero-byte allocations.");
    }
    else
    {
        if (ext) fprintf(ext, "[+] 'mem_alloc' passed zero-byte test.\n\n");
    }

    mem_free(ptr);

    /* Modest-size allocation, should definitely succeed. */
    ptr = mem_alloc(16);
    if (!ptr)
    {
        if (ext) fprintf(ext, "[!] 'mem_alloc' should be able to allocate 16 "
                              "bytes, allocator is probably failing.\n\n");
        fail("'mem_alloc' failed on small allocation.");
    }
    else
    {
        if (ext) fprintf(ext, "[+] 'mem_alloc' passed 16-byte test.\n\n");
    }
    mem_free(ptr);

    pass("Memory allocator appears to be working.");
    
    #else
    
    pass("Cannot test memory allocator, hidden symbols.");
    
    #endif
}
