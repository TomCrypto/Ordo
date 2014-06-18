/* Sample for Ordo - md5sum.c
 * ===============
 *
 * A program which takes a list of files on the command-line, and outputs their
 * md5 checksum. This is essentially a clone of the md5sum utility program, but
 * it only implements the MD5 computation part (no extra features are present).
 *
 * Usage: ./bin/md5sum [path to files ...]
 *
 * This could easily be extended to any hash function, by changing HASH_MD5 to
 * another algorithm (i.e. simply replace the ALG token by something else).
*/

#include <stdlib.h>
#include <stdio.h>

#include "ordo.h"

#define BUFFER_SZ 4096
#define ALG HASH_MD5

static int hash_file(FILE *f, struct DIGEST_CTX *ctx, void *digest)
{
    int err = digest_init(ctx, ALG, 0);
    if (err) return err;

    while (!feof(f))
    {
        unsigned char buffer[BUFFER_SZ]; /* Read file in chunks. */
        size_t len = fread(buffer, 1, sizeof(buffer), f);
        if (len) digest_update(ctx, buffer, len);
    }

    digest_final(ctx, digest);

    return 0;
}

static void print_output(const char *path, const unsigned char *digest)
{
    size_t t = 0;

    for (t = 0; t < digest_length(ALG); ++t)
        printf("%.2x", digest[t]);

    printf("  %s\n", path);
}

int main(int argc, char *argv[])
{
    struct DIGEST_CTX ctx;

    /* Make use of the maximum possible digest length (without parameters that
     * modify output length) to avoid allocations. This is of course optional. */
    unsigned char digest[HASH_DIGEST_LEN];

    if (!prim_avail(ALG))
    {
        printf("Hash algorithm not available!\n");
        return EXIT_FAILURE;
    }

    while (*++argv)
    {
        FILE *f = fopen(*argv, "rb");
        if (!f) perror(*argv);
        else
        {
            int err = hash_file(f, &ctx, digest);
            if (!err) print_output(*argv, digest);
            else printf("Error: %s.\n", ordo_error_msg(err));

            fclose(f);
        }
    }

    return EXIT_SUCCESS;
}
