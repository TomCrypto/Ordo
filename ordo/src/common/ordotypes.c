#include <common/ordotypes.h>

/* Checks whether the next padding bytes at buffer all have the correct padding value. */
inline int padCheck(unsigned char* buffer, unsigned char padding)
{
    /* Iterate over all padding bytes at the end of the block. */
    size_t t;
    for (t = 0; t < padding; t++)
        if ((unsigned char)*(buffer + t) != padding)
            return 0;

    /* All bytes are valid, the padding is acceptable. */
    return 1;
}

/* Xors two buffers together. */
inline void xorBuffer(unsigned char* dst, unsigned char* src, size_t len)
{
    /* Process as many word-size chunks as possible. */
    while (len >= sizeof(size_t))
    {
        *((size_t*)dst) ^= *((size_t*)src);
        dst += sizeof(size_t);
        src += sizeof(size_t);
        len -= sizeof(size_t);
    }

    /* Process any leftover bytes. */
    while (len != 0)
    {
        *(dst++) ^= *(src++);
        len--;
    }
}

/* Increments a counter of arbitrary size as if it were a len-byte integer
   Propagation is done from left-to-right in memory storage order. */
inline void incBuffer(unsigned char* n, size_t len)
{
    /* Increment the first byte. */
    size_t t;
    int carry = (++*n == 0);

    /* Go over each byte, and propagate the carry. */
    for (t = 1; t < len; t++)
    {
        if (carry == 1) carry = (++*(n + t) == 0);
        else return;
    }
}

/* Returns a readable error message. */
char* errorMsg(int code)
{
    /* Get a proper error message. */
    switch (code)
    {
        case ORDO_EFAIL: return "An external error occurred";
        case ORDO_EKEYSIZE: return "The key size is invalid";
        case ORDO_EPADDING: return "The padding block cannot be recognized";
        case ORDO_LEFTOVER: return "There is leftover input data";
    }

    /* Invalid error code... */
    return "Unknown error code";
}
