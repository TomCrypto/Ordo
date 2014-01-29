#include "tests/utility/utils.h"

#define ORDO_INTERNAL_ACCESS

#include "ordo/internal/alg.h"
#include "ordo/internal/sys.h"

/* Tests a bunch of macros used by the library. */
int test_macros(char *output, size_t maxlen, FILE *ext)
{
    if (bits(256) != 32)  fail("The 'bits' macro has failed.");
    if (bytes(32) != 256) fail("The 'bytes' macro has failed.");

    if (min_(1, 2) != 1) fail("The 'min' macro has failed.");
    if (max_(1, 2) != 2) fail("The 'max' macro has failed.");

    pass("Utility macros are working.");
}

int test_pad_check(char *output, size_t maxlen, FILE *ext)
{
    unsigned char buffer[256];
    uint8_t val, r;

    for (val = 1; val < 255; ++val)
    {
        memset(buffer, val, val);

        /* This should pass because all bytes have the same value. */
        if (!pad_check(buffer, val)) fail("'pad_check' has failed.");

        r = random(val);
        if (r == val) --r;
        buffer[random(val)] = r;

        /* This should fail as not all bytes have the same value. */
        if (pad_check(buffer, val)) fail("'pad_check' has failed.");
    }

    pass("'pad_check' is working.");
}

int test_xor_buffer(char *output, size_t maxlen, FILE *ext)
{
    /* We will test the function on small integers only. If it works there,
     * it probably always works, given it is a very generic function. */

    int a, b, out, t;

    for (t = 0; t < 1024; ++t)
    {
        a = random(INT_MAX);
        b = random(INT_MAX);

        out = a ^ b; /* Expected output. */

        xor_buffer((unsigned char*)&a, (unsigned char*)&b, sizeof(int));
        if (a != out) fail("'xor_buffer' has failed.");
    }

    /* Check the function works properly when fed the same buffers. */
    xor_buffer((unsigned char *)&a, (unsigned char *)&a, sizeof(int));
    if (a != 0) fail("'xor_buffer' has failed.");

    /* Finally, check the function does nothing on zero-length inputs. */
    a = 0x5a;
    xor_buffer((unsigned char *)&a, (unsigned char *)&a, 0);
    if (a != 0x5a) fail("'xor_buffer' has failed.");

    pass("'xor_buffer' is working.");
}

int test_inc_buffer(char *output, size_t maxlen, FILE *ext)
{
    /* First check that a zero-byte buffer does nothing. */
    unsigned char buffer[3] = { 0, 0, 0 };

    if (ext) fprintf(ext, "[*] Starting 'inc_buffer' tests.\n\n");

    inc_buffer(buffer, 0);

    if (ext) fprintf(ext, "[*] Checking inc_buffer on 0-length input.\n\n");
    if ((buffer[0] != 0) || (buffer[1] != 0) || (buffer[2] != 0))
    {
        if (ext) fprintf(ext, "[!] Buffer was modified - invalid.\n\n");
        fail("'inc_buffer' has failed.");
    }

    /* { 0, 0, 0 } -> { 1, 0, 0 } */
    if (ext) fprintf(ext, "[*] Checking inc_buffer({ 0, 0, 0 })\n\n");
    inc_buffer(buffer, sizeof(buffer));
    if (!((buffer[0] == 1) && (buffer[1] == 0) && (buffer[2] == 0)))
    {
        if (ext) fprintf(ext, "[!] Expected { 1, 0, 0 },"
                              " got { %d, %d, %d }.\n\n",
                         buffer[0], buffer[1], buffer[2]);
        fail("'inc_buffer' has failed.");
    }

    /* Should wrap around: { 0xff, 0, 0 } -> { 0, 1, 0 } */
    if (ext) fprintf(ext, "[*] Checking inc_buffer({ 0xff, 0, 0 })\n\n");
    buffer[0] = 0xff;
    inc_buffer(buffer, sizeof(buffer));
    if (!((buffer[0] == 0) && (buffer[1] == 1) && (buffer[2] == 0)))
    {
        if (ext) fprintf(ext, "[!] Expected { 0, 1, 0 },"
                              " got { %d, %d, %d }.\n\n",
                         buffer[0], buffer[1], buffer[2]);
        fail("'inc_buffer' has failed.");
    }

    /* { 0xff, 0xff, 5 } -> { 0, 0, 6 } */
    if (ext) fprintf(ext, "[*] Checking inc_buffer({ 0xff, 0xff, 5 })\n\n");
    buffer[0] = 0xff;
    buffer[1] = 0xff;
    buffer[2] = 5;
    inc_buffer(buffer, sizeof(buffer));
    if (!((buffer[0] == 0) && (buffer[1] == 0) && (buffer[2] == 6)))
    {
        if (ext) fprintf(ext, "[!] Expected { 0, 0, 6 },"
                              " got { %d, %d, %d }.\n\n",
                         buffer[0], buffer[1], buffer[2]);
        fail("'inc_buffer' has failed.");
    }


    /* { 0xff, 0xff, 0xff } -> { 0, 0, 0 } (full wrap-around) */
    if (ext) fprintf(ext, "[*] Checking inc_buffer({ 0xff, 0xff, 0xff })\n\n");
    buffer[0] = 0xff;
    buffer[1] = 0xff;
    buffer[2] = 0xff;
    inc_buffer(buffer, sizeof(buffer));
    if (!((buffer[0] == 0) && (buffer[1] == 0) && (buffer[2] == 0)))
    {
        if (ext) fprintf(ext, "[!] Expected { 0, 0, 0 },"
                              " got { %d, %d, %d }.\n\n",
                         buffer[0], buffer[1], buffer[2]);
        fail("'inc_buffer' has failed.");
    }

    if (ext) fprintf(ext, "[*] Checking inc_buffer on length 1 inputs is the "
                          "same as incrementing a uint8_t.\n\n");
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
                if (ext)
                {
                    fprintf(ext, "[!] Check failed: inc_buffer({ %d }), "
                                 "expected { %d }, got { %d }.\n\n",
                                  y - 1, x, y);
                }
                fail("'inc_buffer' has failed.");
            }
        }
    }

    pass("'inc_buffer' is working.");
}
