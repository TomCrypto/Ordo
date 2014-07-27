/*===-- info.c -----------------------------------------*- SAMPLE -*- C -*-===*/
/**
*** @file
*** @brief Sample
***
*** This sample will enumerate all available block ciphers, and will print out
*** the key lengths they accept. It shows how to use the limit API to discover
*** key lengths, and how to iterate on them - note in practice you do not need
*** to iterate, since you already know the length of your key material, so you
*** only need to find the next largest admissible key length.
**/
/*===----------------------------------------------------------------------===*/

#include <stdlib.h>
#include <stdio.h>
#include "ordo.h"

int main(void)
{
    const prim_t *cipher;
    int err;

    /* The prims_by_type() function gives a zero-terminated array */
    for (cipher = prims_by_type(PRIM_TYPE_BLOCK); *cipher; ++cipher)
    {
        struct BLOCK_LIMITS limits;
        size_t key_len;

        if ((err = block_limits(*cipher, &limits)))
            return printf("Error: %s.\n", ordo_error_msg(err)), EXIT_FAILURE;

        printf("%s:\n", prim_name(*cipher));

        for (key_len  = limits.key_min;
             key_len <= limits.key_max;
             key_len += limits.key_mul)
            printf("  * %d bits\n", (int)key_len * 8);

        if (*(cipher + 1)) printf("\n");
    }

    return EXIT_SUCCESS;
}
