/* Sample for Ordo - info.c
 * ===============
 *
 * Shows how to discover cipher key lengths. The basic idea is that, given some
 * valid key length K, if key_len(K + 1) == K, then K is the largest key length
 * accepted by the cipher - this allows one to easily iterate through valid key
 * lengths, which is important when the key length is not known in advance.
 *
 * In practice, though, you don't iterate them, and only need to make one call.
*/

#include <stdlib.h>
#include <stdio.h>

#include "ordo.h"

int main(void)
{
    const prim_t *cipher;

    for (cipher = prims_by_type(PRIM_TYPE_BLOCK); *cipher; ++cipher)
    {
        size_t key_len, last_len = (size_t)(-1);

        printf("%s:\n", prim_name(*cipher));
        
        for (key_len = block_cipher_query(*cipher, KEY_LEN_Q, 0);
             key_len != last_len; /* This is a way to iterate them. */
             key_len = block_cipher_query(*cipher, KEY_LEN_Q, key_len + 1))
        {
            printf("  * %d bits (%d bytes)\n", (int)key_len * 8,
                                               (int)key_len);
            last_len = key_len;
        }

        if (*(cipher + 1))
            printf("\n");
    }

    return EXIT_SUCCESS;
}
