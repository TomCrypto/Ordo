/* Sample: md5sum - calculates the MD5 digest of the file located at argv[1].
 * 
 * Usage: ./bin/md5sum [path to file]
 *
 * Comments: This is essentially a clone of the md5sum utility program.
*/

#include <stdio.h>

#include "ordo.h"

static int md5_file(FILE *f, struct DIGEST_CTX *ctx, void *digest)
{
    static char buffer[4096];

    int err = digest_init(ctx, 0); /* No parameters required. */
    if (err) return err;

    while (!feof(f))
    {
        size_t len = fread(buffer, 1, sizeof(buffer), f);
        if (len) digest_update(ctx, buffer, len);
    }

    digest_final(ctx, digest);
    digest_free(ctx);
    return 0;
}

static void print_output(const char *path,
                         const unsigned char *digest,
                         size_t len)
{
    while (len--) printf("%.2x", *(digest++));
    printf("  %s\n", path);
}

int main(int argc, char *argv[])
{
    struct DIGEST_CTX *ctx;
    unsigned char *digest;
    size_t digest_len;
    FILE *f;
    int err;

    /* Do some error checking, initialize all resources as needed. */

    if (argc != 2)
    {
        printf("No file specified.\n");
        return EXIT_FAILURE;
    }

    if (ordo_init())
    {
        printf("Failed to initialize Ordo.\n");
        return EXIT_FAILURE;
    }

    digest_len = digest_length(md5());
    if (!(digest = malloc(digest_len)))
    {
        printf("Failed to allocate memory.\n");
        return EXIT_FAILURE;
    }

    if (!(ctx = digest_alloc(md5())))
    {
        free(digest);
        printf("Failed to allocate context.\n");
        return EXIT_FAILURE;
    }

    f = fopen(argv[1], "rb");
    if (!f)
    {
        free(digest);
        digest_free(ctx);
        printf("Failed to open '%s'.\n", argv[1]);
        return EXIT_FAILURE;
    }

    /* Attempt to calculate the MD5 digest of the file. */

    if ((err = md5_file(f, ctx, digest)))
    {
        fclose(f);
        free(digest);
        digest_free(ctx);
        printf("An error occurred: %s.\n", error_msg(err));
        return EXIT_FAILURE;
    }

    print_output(argv[1], digest, digest_len);
    return EXIT_SUCCESS;
}
