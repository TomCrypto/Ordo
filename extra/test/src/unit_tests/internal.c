/*===-- unit_tests/internal.c ----------------------------*- TEST -*- C -*-===*/
/**
*** @file
*** @brief Test Vectors
***
*** This unit tests the internal library utilities.
**/
/*===----------------------------------------------------------------------===*/

#include "testenv.h"

/*===----------------------------------------------------------------------===*/

#if defined(ORDO_STATIC_LIB)

#define ORDO_INTERNAL_ACCESS
#include "ordo/internal/implementation.h"
#undef ORDO_INTERNAL_ACCESS

int test_macros(void);
int test_macros(void)
{
    ASSERT_EQ(bits(256), 32);
    ASSERT_EQ(bytes(32), 256);

    ASSERT_EQ(smin(1, 2), 1);
    ASSERT_EQ(smax(1, 2), 2);

    return 1;
}

int test_pad_check(void);
int test_pad_check(void)
{
    unsigned char buffer[256];
    uint16_t r, val;

    for (r = 0; r < 256; ++r)
        for (val = 1; val < 256; ++val)
        {
            memset(buffer, (uint8_t)val, (size_t)val);

            /* This should pass because all bytes have the same value. */
            ASSERT(pad_check(buffer, (uint8_t)val));

            if (r < val)
            {
                buffer[r] = (uint8_t)r;

                /* This should fail as not all bytes have the same value. */
                ASSERT(!pad_check(buffer, (uint8_t)val));
            }
        }

    return 1;
}

int test_xor_buffer(void);
int test_xor_buffer(void)
{
    /* We will test the function on small integers only. If it works there,
     * it probably always works, given it is a very generic function. */

    uint32_t a, b, out, t;

    for (t = 0; t < 1024; ++t)
    {
        a = (uint32_t)t * 7919;
        b = (uint32_t)t * 3637;

        out = a ^ b; /* Expected output. */

        xor_buffer((unsigned char *)&a, (const unsigned char *)&b,
                   sizeof(uint32_t));
        ASSERT_EQ(a, out);
    }

    /* Check the function works properly when fed the same buffers. */
    xor_buffer((unsigned char *)&a, (const unsigned char *)&a,
               sizeof(uint32_t));
    ASSERT_EQ(a, 0);

    /* Finally, check the function does nothing on zero-length inputs. */
    a = 0x5a;
    xor_buffer((unsigned char *)&a, (const unsigned char *)&a, 0);
    ASSERT_EQ(a, 0x5a);

    return 1;
}

int test_inc_buffer(void);
int test_inc_buffer(void)
{
    /* First check that a zero-byte buffer does nothing. */
    unsigned char buffer[3] = { 0, 0, 0 };

    inc_buffer(buffer, 0);

    ASSERT((buffer[0] == 0) && (buffer[1] == 0) && (buffer[2] == 0));

    /* { 0, 0, 0 } -> { 1, 0, 0 } */
    inc_buffer(buffer, sizeof(buffer));
    ASSERT((buffer[0] == 1) && (buffer[1] == 0) && (buffer[2] == 0));

    /* Should wrap around: { 0xff, 0, 0 } -> { 0, 1, 0 } */
    buffer[0] = 0xff;
    inc_buffer(buffer, sizeof(buffer));
    ASSERT((buffer[0] == 0) && (buffer[1] == 1) && (buffer[2] == 0));

    /* { 0xff, 0xff, 5 } -> { 0, 0, 6 } */
    buffer[0] = 0xff;
    buffer[1] = 0xff;
    buffer[2] = 5;
    inc_buffer(buffer, sizeof(buffer));
    ASSERT((buffer[0] == 0) && (buffer[1] == 0) && (buffer[2] == 6));

    /* { 0xff, 0xff, 0xff } -> { 0, 0, 0 } (full wrap-around) */
    buffer[0] = 0xff;
    buffer[1] = 0xff;
    buffer[2] = 0xff;
    inc_buffer(buffer, sizeof(buffer));
    ASSERT((buffer[0] == 0) && (buffer[1] == 0) && (buffer[2] == 0));

    {
        /* Finally, try it on a single-byte buffer. The function should be
         * equivalent to 8-bit addition by definition. */
        uint8_t x = 0, y = 0;
        uint16_t t;

        for (t = 0; t < 1024; ++t)
        {
            x += 1;
            inc_buffer((unsigned char *)&y, sizeof(y));
            ASSERT_EQ(x, y);
        }
    }

    return 1;
}

#endif
