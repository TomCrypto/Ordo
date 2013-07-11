#include <tests/utility/mem.h>

/* Note: you should NEVER include any internal header in your code, nor use
 * any such internal functions, but here it's fine because we are actually
 * testing those functions. */
#include <internal/mem.h>

int test_mem(char *output, int maxlen, FILE *ext)
{
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
}
