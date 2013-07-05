#include <common/ordo_utils.h>

/******************************************************************************/

int pad_check(const unsigned char *buffer, uint8_t padding)
{
    size_t t;

    for (t = 0; t < padding; t++)
        if (buffer[t] != padding) return 0;

    return 1;
}

void xor_buffer(unsigned char *dst, const unsigned char *src, size_t len)
{
    while (len--) *dst++ ^= *src++;
}

void inc_buffer(unsigned char *buffer, size_t len)
{
    size_t carry = 1;
    size_t t = 0;

    while (carry && (++t <= len)) carry = (++*(buffer + t - 1) == 0);
}
