/*===-- samples/info.c -------------------------------*- PUBLIC -*- H -*-===*/
/**
*** @file
*** @brief Sample
***
*** This sample will enumerate all available block ciphers, and will print out
*** the key lengths they accept. It shows how to use the query API to discover
*** key lengths, and how to iterate on them - note in practice you do not need
*** to iterate, since you already know the length of your key material, so you
*** only need to query the next best key length once.
**/
/*===----------------------------------------------------------------------===*/

#include <stdlib.h>
#include <stdio.h>

#include "ordo.h"

int main(void)
{
    const prim_t *cipher;

    /* The prims_by_type() function gives a zero-terminated array */
    for (cipher = prims_by_type(PRIM_TYPE_BLOCK); *cipher; ++cipher)
    {
        size_t key_len, last_len = (size_t)(-1);

        printf("%s:\n", prim_name(*cipher));

        for (key_len = block_query(*cipher, KEY_LEN_Q, 0);
             key_len != last_len; /* Iterate them e.g. like this. */
             key_len = block_query(*cipher, KEY_LEN_Q, key_len + 1))
        {
            printf("  * %d bits\n", (int)key_len * 8);
            last_len = key_len; /* Until they match */
        }

        if (*(cipher + 1)) printf("\n");
    }

    return EXIT_SUCCESS;
}
