/* Shows how to discover cipher key lengths. The basic idea is that, given some
 * valid key length K, if key_len(K + 1) == K, then K is the largest key length
 * accepted by the cipher - this allows one to easily iterate through valid key
 * lengths.
*/

#include <stdlib.h>
#include <stdio.h>

#include <ordo.h>

int main()
{
    size_t t;

    ordo_init();

    for (t = 0; t < BLOCK_COUNT; ++t)
    {
        const struct BLOCK_CIPHER *cipher = block_cipher_by_id(t);
        size_t key_len = block_cipher_key_len(cipher, 0);

        printf("Key lengths for %s:\n", block_cipher_name(cipher));

        while (1)
        {
            size_t next_len = block_cipher_key_len(cipher, key_len + 1);
            printf("* %d bits.\n", (int)key_len * 8);
            if (next_len == key_len) break;
            key_len = next_len;
        }

        printf("\n");
    }

    return EXIT_SUCCESS;
}
