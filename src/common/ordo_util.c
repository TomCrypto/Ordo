#include <common/ordo_utils.h>

#include <common/ordo_errors.h>

#include <stdlib.h>
#include <stdint.h>

/******************************************************************************/

/* Checks whether the next padding bytes at buffer all have the correct padding value. */
int pad_check(const unsigned char* buffer, unsigned char padding)
{
    /* Iterate over all padding bytes at the end of the block. */
    size_t t;
    for (t = 0; t < padding; t++)
        if (buffer[t] != padding)
            return 0;

    /* All bytes are valid, the padding is acceptable. */
    return 1;
}

/* Xors two buffers together. */
void xor_buffer(unsigned char* dst, const unsigned char* src, size_t len)
{
    /* Optimization will do the rest. */
    while (len--) *(dst++) ^= *(src++);
}

/* Increments a counter of arbitrary size as if it were a len-byte integer
   Propagation is done from left-to-right in memory storage order. */
void inc_buffer(unsigned char* buffer, size_t len)
{
    /* Set the initial carry to one. */
    size_t carry = 1;
    size_t t = 0;

    /* Go over each byte, and propagate the carry. */
    while (carry && (++t <= len)) carry = (++*(buffer + t - 1) == 0);
}

/* Returns a readable error message. */
const char* error_msg(int code)
{
    /* Get a proper error message. */
    switch (code)
    {
        case ORDO_SUCCESS: return "No error occurred.";
        case ORDO_ARG: return "Invalid argument provided.";
        case ORDO_FAIL: return "An external error occurred";
        case ORDO_KEY_SIZE: return "The key size is invalid";
        case ORDO_PADDING: return "The padding block cannot be recognized";
        case ORDO_LEFTOVER: return "There is leftover input data";
        case ORDO_ALLOC: return "Memory allocation failed";
    }

    /* Invalid error code... */
    return "Unknown error code";
}
