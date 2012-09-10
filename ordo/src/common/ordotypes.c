#include <common/ordotypes.h>

/* Checks whether the next padding bytes at buffer all have the correct padding value. */
inline int padCheck(unsigned char* buffer, unsigned char padding)
{
    /* Iterate over all padding bytes at the end of the block. */
    size_t t;
    for (t = 0; t < padding; t++)
        if (*(buffer + t) != padding)
            return 0;

    /* All bytes are valid, the padding is acceptable. */
    return 1;
}

/* Xors two buffers together. */
inline void xorBuffer(unsigned char* dst, unsigned char* src, size_t len)
{
    /* Optimization will do the rest. */
    while (len--) *(dst++) ^= *(src++);
}

/* Increments a counter of arbitrary size as if it were a len-byte integer
   Propagation is done from left-to-right in memory storage order. */
inline void incBuffer(unsigned char* n, size_t len)
{
    /* Set the initial carry to one. */
    size_t carry = 1;
    size_t t = 0;

    /* Go over each byte, and propagate the carry. */
    while (carry && (++t <= len)) carry = (++*(n + t - 1) == 0);
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
        case ORDO_ELEFTOVER: return "There is leftover input data";
        case ORDO_EHEAPALLOC: return "Heap allocation failed";
    }

    /* Invalid error code... */
    return "Unknown error code";
}
