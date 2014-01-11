/* Shows how to discover cipher key lengths. The basic idea is that, given some
 * valid key length K, if key_len(K + 1) == K, then K is the largest key length
 * accepted by the cipher - this allows one to easily iterate through valid key
 * lengths.
*/

#include <stdlib.h>
#include <stdio.h>

#include "ordo.h"

int main()
{
    size_t t;

    if (ordo_init())
    {
        printf("Failed to initialize Ordo.\n");
        return EXIT_FAILURE;
    }

    for (t = 0; t < block_cipher_count(); ++t)
    {
        const struct BLOCK_CIPHER *cipher = block_cipher_by_index(t);
        size_t key_len = block_cipher_query(cipher, KEY_LEN_Q, 0);

        printf("Key lengths for %s:\n", block_cipher_name(cipher));

        while (1)
        {
            size_t next = block_cipher_query(cipher, KEY_LEN_Q, key_len + 1);
            printf("* %d bits.\n", (int)key_len * 8);
            if (next == key_len) break;
            key_len = next;
        }

        printf("\n");
    }

    return EXIT_SUCCESS;
}
