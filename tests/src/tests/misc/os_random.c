#include <tests/misc/os_random.h>

#include <misc/os_random.h>

int test_os_random(char *output, int maxlen, FILE *ext)
{
    uint8_t buffer[1024];
    int t;

    memset(buffer, 0x00, sizeof(buffer));
    if (os_random(&buffer, sizeof(buffer)))
    {
        fail("'os_random' reported failure (does OS provide one?)");
    }

    /* Just do a rudimentary check that the buffer was actually changed. */
    for (t = 0; t < 1024; ++t)
    {
        if (buffer[t] != 0) pass("'os_random' appears to be working.");
    }

    /* Chances of a false positive are 256^(-1024) (read: non-existent). */
    fail("'os_random' reports success but non-random output.");
}
