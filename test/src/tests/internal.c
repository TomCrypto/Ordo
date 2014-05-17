#include "testenv.h"

#include <string.h>
#include "ordo.h"

#if defined(ORDO_STATIC_LIB)

#define ORDO_INTERNAL_ACCESS

#include "ordo/internal/implementation.h"

#undef ORDO_INTERNAL_ACCESS

int test_alg(void)
{
    return 1;
}

int test_sys(void)
{
    return 1;
}

/* Tests a bunch of macros used by the library. */
int test_macros(void)
{
    if (bits(256) != 32)  FAIL("The 'bits' macro has failed.");
    if (bytes(32) != 256) FAIL("The 'bytes' macro has failed.");

    if (smin(1, 2) != 1) FAIL("The 'min' macro has failed.");
    if (smax(1, 2) != 2) FAIL("The 'max' macro has failed.");

    return 1;
}

int test_pad_check(void)
{
    unsigned char buffer[256];
    uint8_t val, r;

    for (val = 1; val < 255; ++val)
    {
        memset(buffer, val, val);

        /* This should pass because all bytes have the same value. */
        if (!pad_check(buffer, val)) FAIL("'pad_check' has failed.");

        r = random(val);
        if (r == val) --r;
        buffer[random(val)] = r;

        /* This should fail as not all bytes have the same value. */
        if (pad_check(buffer, val)) FAIL("'pad_check' has failed.");
    }

    return 1;
}

int test_xor_buffer(void)
{
    /* We will test the function on small integers only. If it works there,
     * it probably always works, given it is a very generic function. */

    int a, b, out, t;

    for (t = 0; t < 1024; ++t)
    {
        a = random(32768);
        b = random(32768);

        out = a ^ b; /* Expected output. */

        xor_buffer((unsigned char*)&a, (unsigned char*)&b, sizeof(int));
        if (a != out) FAIL("'xor_buffer' has failed.");
    }

    /* Check the function works properly when fed the same buffers. */
    xor_buffer((unsigned char *)&a, (unsigned char *)&a, sizeof(int));
    if (a != 0) FAIL("'xor_buffer' has failed.");

    /* Finally, check the function does nothing on zero-length inputs. */
    a = 0x5a;
    xor_buffer((unsigned char *)&a, (unsigned char *)&a, 0);
    if (a != 0x5a) FAIL("'xor_buffer' has failed.");

    return 1;
}

int test_inc_buffer(void)
{
    /* First check that a zero-byte buffer does nothing. */
    unsigned char buffer[3] = { 0, 0, 0 };

    inc_buffer(buffer, 0);

    if ((buffer[0] != 0) || (buffer[1] != 0) || (buffer[2] != 0))
    {
        FAIL("'inc_buffer' has failed.");
    }

    /* { 0, 0, 0 } -> { 1, 0, 0 } */
    inc_buffer(buffer, sizeof(buffer));
    if (!((buffer[0] == 1) && (buffer[1] == 0) && (buffer[2] == 0)))
    {
        FAIL("'inc_buffer' has failed.");
    }

    /* Should wrap around: { 0xff, 0, 0 } -> { 0, 1, 0 } */
    buffer[0] = 0xff;
    inc_buffer(buffer, sizeof(buffer));
    if (!((buffer[0] == 0) && (buffer[1] == 1) && (buffer[2] == 0)))
    {
        FAIL("'inc_buffer' has failed.");
    }

    /* { 0xff, 0xff, 5 } -> { 0, 0, 6 } */
    buffer[0] = 0xff;
    buffer[1] = 0xff;
    buffer[2] = 5;
    inc_buffer(buffer, sizeof(buffer));
    if (!((buffer[0] == 0) && (buffer[1] == 0) && (buffer[2] == 6)))
    {
        FAIL("'inc_buffer' has failed.");
    }


    /* { 0xff, 0xff, 0xff } -> { 0, 0, 0 } (full wrap-around) */
    buffer[0] = 0xff;
    buffer[1] = 0xff;
    buffer[2] = 0xff;
    inc_buffer(buffer, sizeof(buffer));
    if (!((buffer[0] == 0) && (buffer[1] == 0) && (buffer[2] == 0)))
    {
        FAIL("'inc_buffer' has failed.");
    }

    {
        /* Finally, try it on a single-byte buffer. The function should be
         * equivalent to 8-bit addition by definition. */
        uint8_t x = 0, y = 0;
        int t;

        for (t = 0; t < 1024; ++t)
        {
            x += 1;
            inc_buffer((unsigned char *)&y, sizeof(y));
            if (x != y)
            {
                FAIL("'inc_buffer' has failed.");
            }
        }
    }

    return 1;
}

#endif
