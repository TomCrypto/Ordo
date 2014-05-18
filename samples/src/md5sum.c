/* Sample for Ordo - md5sum.c
 * ===============
 *
 * A program which takes a list of files on the command-line, and outputs their
 * md5 checksum. This is essentially a clone of the md5sum utility program, but
 * it only implements the MD5 computation part (no extra features are present).
 *
 * Usage: ./bin/md5sum [path to files ...]
 *
 * This could easily be extended to any hash function, by changing md5() into a
 * different algorithm, and adjusting the digest buffer's size, here 16 bytes.
*/

#include <stdlib.h>
#include <stdio.h>

#include "ordo.h"

#define DIGEST_SZ 16
#define BUFFER_SZ 4096

static int md5_file(FILE *f, struct DIGEST_CTX *ctx, void *digest)
{
    int err = digest_init(ctx, HASH_MD5, 0);
    if (err) return err;

    while (!feof(f))
    {
        unsigned char buffer[BUFFER_SZ]; /* Read in by chunks. */
        size_t len = fread(buffer, 1, sizeof(buffer), f);
        if (len) digest_update(ctx, buffer, len);
    }

    digest_final(ctx, digest);

    return 0;
}

static void print_output(const char *path, const unsigned char *digest)
{
    size_t t = 0;

    for (t = 0; t < DIGEST_SZ; ++t)
        printf("%.2x", digest[t]);

    printf("  %s\n", path);
}

int main(int argc, char *argv[])
{
    struct DIGEST_CTX ctx;

    while (*++argv)
    {
        FILE *f = fopen(*argv, "rb");
        if (!f) perror(*argv);
        else
        {
            unsigned char digest[DIGEST_SZ];
            int err = md5_file(f, &ctx, digest);
            if (!err) print_output(*argv, digest);
            else printf("Error: %s.\n", ordo_error_msg(err));

            fclose(f);
        } 
    }

    return EXIT_SUCCESS;
}
