#include <stdio.h>
#include <string.h>

#include <common/ordo_utils.h> /* error_msg() */
#include <enc/enc_block.h> /* encrypt */
#include <ordo.h> /* init */
#include <kdf/pbkdf2.h>
#include <random/random.h>

#define BUF_SIZE 4096
#define KEY_LEN 32
#define SALT_LEN 12

/* Usage: encrypt d/e KEY IN OUT */
int main(int argc, char *argv[])
{
    if (argc != 5) return -1;

    load_ordo();

    /* Open the files. */
    FILE *in = fopen(argv[3], "rb");
    FILE *out = fopen(argv[4], "wb");

    /* "e" for encrypt, "d" (or anything else) for decrypt. */
    int direction = (strcmp(argv[1], "e") == 0) ? 1 : 0;

    /* If encrypting, generate random salt and IV. */
    unsigned char *iv = malloc(cipher_block_size(Threefish256()));
    unsigned char *salt = malloc(SALT_LEN); // arbitrary

    if (direction) // encrypting?
    {
        /* random salt/IV */
        ordo_random(salt, SALT_LEN);
        ordo_random(iv, digest_length(Skein256()));
    }
    else
    {
        /* If decrypting, read them from encrypted file's header. */
        /* header: [salt][iv][fingerprint] */
        fread(salt, 1, SALT_LEN, in);
        fread(iv, 1, cipher_block_size(Threefish256()), in);
    }

    unsigned char *key = malloc(KEY_LEN); /* arbitrary */
    unsigned char *fingerprint = malloc(digest_length(Skein256()));

    int err = pbkdf2(Skein256(), argv[2], strlen(argv[2]),
                     salt, SALT_LEN, key, KEY_LEN, 100000, 0); /* no params */

    /* key is encryption key - hash it once for fingerprint. */
    struct DIGEST_CTX *hash = digest_alloc(Skein256());
    digest_init(hash, 0);
    digest_update(hash, key, KEY_LEN);
    digest_final(hash, fingerprint);
    digest_free(hash);

    if (err)
    {
        printf("Error! %s.\n", error_msg(err));
        return -1;
    }

    /* Now if we are encrypting, store data in output file. */
    if (direction)
    {
        fwrite(salt, 1, SALT_LEN, out);
        fwrite(iv, 1, cipher_block_size(Threefish256()), out);
        fwrite(fingerprint, 1, digest_length(Skein256()), out);
    }
    else
    {
        /* If we are decrypting, verify the key instead. */
        unsigned char *file_fingerprint = malloc(digest_length(Skein256()));
        fread(file_fingerprint, 1, digest_length(Skein256()), in);

        if (memcmp(file_fingerprint, fingerprint, digest_length(Skein256())) != 0)
        {
            printf("Wrong key!\n");
            /* delete out file (it was created empty with fopen) */
            /* this is bad design but what the hell.. */
            remove(argv[4]);
            return -1;
        }
    }

    /* Now we can just encrypt or decrypt the rest of the data. */
    size_t iv_len = cipher_block_size(Threefish256());
    struct ENC_BLOCK_CTX *ctx = enc_block_alloc(Threefish256(), CTR());
    enc_block_init(ctx, key, KEY_LEN, iv, iv_len, direction, 0, 0); /* no params */

    unsigned char *buffer = malloc(BUF_SIZE);

    while (!feof(in))
    {
        size_t len = fread(buffer, 1, BUF_SIZE, in);
        /* encrypt buffer -> buffer in place (always supported). */
        enc_block_update(ctx, buffer, len, buffer, &len);
        fwrite(buffer, 1, len, out);
    }

    enc_block_final(ctx, 0, 0); /* CTR mode leaves nothing */
    /* though this should be checked anyway for consistency. */

    enc_block_free(ctx);

    fclose(in);
    fclose(out);
    /* other cleanup.. zzz */
    return 0;
}
