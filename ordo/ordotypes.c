#include "ordotypes.h"

/* Checks whether the next padding bytes at buffer all have the correct padding value. */
int padcheck(unsigned char* buffer, unsigned char padding)
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
void XOR(unsigned char* val, unsigned char* mod, size_t len)
{
    while (len != 0)
    {
        *val ^= *mod;
        val++;
        mod++;
        len--;
    }
}

/* Increments a counter of arbitrary size as if it were a len-byte integer
   Propagation is done from left-to-right in memory storage order. */
void incCounter(unsigned char* iv, size_t len)
{
	/* Increment the first byte. */
	size_t t;
	int carry = (++*iv == 0);

	/* Go over each byte, and propagate the carry. */
	for (t = 1; t < len; t++)
	{
		if (carry == 1) carry = (++*(iv + t) == 0);
		else break;
	}
}
