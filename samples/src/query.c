/* Shows how to use the query codes along with user input to decide on an
 * appropriate key length to a user password. */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "ordo.h"

static void prompt_user(char *prompt, char *buffer, int max_len)
{
    printf("%s", prompt);
    if (fgets(buffer, max_len, stdin))
    {
        size_t len = strlen(buffer);
        if ((len > 0) && (buffer[len - 1] == '\n')) buffer[len - 1] = '\0';
    }
}

int main()
{
    if (ordo_init())
    {
        printf("Failed to initialize Ordo.\n");
        return EXIT_FAILURE;
    }
    else
    {
        const struct BLOCK_CIPHER *cipher;
        char cipher_s[32], pwd_s[32];
        
        prompt_user("Cipher to use: ", cipher_s, sizeof(cipher_s));
        prompt_user("Type password: ", pwd_s, sizeof(pwd_s));
        
        cipher = block_cipher_by_name(cipher_s);
        if (!cipher)
        {
            printf("Cipher not recognized!\n");
            return EXIT_FAILURE;
        }
        else
        {
            size_t pwd_len = strlen(pwd_s);
            size_t key_len = block_cipher_query(cipher, KEY_LEN, pwd_len);
        
            printf("Password is %d bytes long. Conservatively, the best key"
                   "length to use for this cipher is... %d bits.\n",
                   (int)pwd_len, (int)bytes(key_len));
        }
        
        return EXIT_SUCCESS;
    }
}
