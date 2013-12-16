#include "ordo/common/utils.h"

/******************************************************************************/

int ORDO_CALLCONV
pad_check(const unsigned char *buffer, uint8_t padding)
{
    size_t t;

    for (t = 0; t < padding; t++)
        if (buffer[t] != padding) return 0;

    return 1;
}

void ORDO_CALLCONV
xor_buffer(void *dst, const void *src, size_t len)
{
    while (len--)
    {
        *(unsigned char *)dst = *(unsigned char *)dst
                              ^ *(unsigned char *)src;

        dst = offset(dst, 1);
        src = offset(src, 1);
    }
}

void ORDO_CALLCONV
inc_buffer(unsigned char *buffer, size_t len)
{
    size_t carry = 1;
    size_t t = 0;

    while (carry && (++t <= len)) carry = (++*(buffer + t - 1) == 0);
}
