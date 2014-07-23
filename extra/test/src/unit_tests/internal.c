/*===-- unit_tests/internal.c ----------------------------*- TEST -*- C -*-===*/
/**
*** @file
*** @brief Test Vectors
***
*** This unit tests the internal library utilities.
**/
/*===----------------------------------------------------------------------===*/

#include "testenv.h"

#if !defined(ORDO_STATIC_LIB)
    #error "Tests require static linkage to the library!"
#else
    #define ORDO_INTERNAL_ACCESS
#endif

#include "ordo/internal/implementation.h"

/*===----------------------------------------------------------------------===*/

int test_macros(void);
int test_macros(void)
{
    ASSERT_EQ(bits(256), 32);
    ASSERT_EQ(bytes(32), 256);

    ASSERT_EQ(smin(1, 2), 1);
    ASSERT_EQ(smax(1, 2), 2);

    return 1;
}

static void gen_msg(unsigned char *buf, size_t msg_len, size_t block_len)
{
    uint8_t val = 1, pad =  (uint8_t)(block_len - msg_len);
    size_t pad_len = block_len - msg_len;

    while (msg_len--)
        *(buf++) = (val = 3 * val + 1);

    while (pad_len--)
        *(buf++) = pad;
}

int test_pad_check(void);
int test_pad_check(void)
{
    unsigned char buffer[256];
    size_t t, p;

    for (t = 1; t < 32; ++t)
    {
        gen_msg(buffer, t, 32);
        ASSERT_EQ(pad_check(buffer, 32), t);
    }

    for (t = 1; t < 32; ++t)
        for (p = t; p < 32; ++p)
        {
            gen_msg(buffer, t, 32);
            buffer[p] ^= 0x01;

            ASSERT(!pad_check(buffer, 32));
        }

    gen_msg(buffer, 40, 80);

    ASSERT(!pad_check(buffer, 0));
    ASSERT(!pad_check(buffer, 32));
    ASSERT(!pad_check(buffer, 33));
    ASSERT(!pad_check(buffer, 256));
    ASSERT(!pad_check(buffer, 257));

    memset(buffer, 0xB1, 177);
    ASSERT_EQ(pad_check(buffer, 177), 177);

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

        xor_buffer(&a, &b, sizeof(uint32_t));
        ASSERT_EQ(a, out);
    }

    /* Finally, check the function does nothing on zero-length inputs. */
    a = 0x5a;
    xor_buffer(&a, &b, 0);
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
