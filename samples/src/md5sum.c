/* Sample: md5sum - calculates the MD5 digest of argv[1].
 * Basically a clone of the md5sum utility. */

#include <stdio.h>

#include "ordo.h"

#define BUF_SIZE 4096

/* Usage: md5sum FILENAME */
int main(int argc, char *argv[])
{
    int err;
    FILE *f;
    size_t t;
    unsigned char *buffer, *digest;

    if (argc != 2) return -1;
    f = fopen(argv[1], "rb");
    if (!f)
    {
        printf("Failed to open %s.\n", argv[1]);
        return EXIT_FAILURE;
    }

    if (ordo_init())
    {
        printf("Failed to initialize Ordo.\n");
        return EXIT_FAILURE;
    }

    struct DIGEST_CTX *ctx = digest_alloc(md5());
    if (!ctx)
    {
        printf("Failed to allocate memory.\n");
        return EXIT_FAILURE;
    }

    if ((err = digest_init(ctx, 0))) /* no params */
    {
        printf("An error occurred: %s.\n", error_msg(err));
        digest_free(ctx);
        return -1;
    }

    buffer = malloc(BUF_SIZE);

    while (!feof(f))
    {
        size_t len = fread(buffer, 1, BUF_SIZE, f);
        digest_update(ctx, buffer, len);
    }

    free(buffer);
    fclose(f);

    digest = malloc(digest_length(md5()));
    digest_final(ctx, digest);
    digest_free(ctx);

    for (t = 0; t < digest_length(md5()); ++t)
        printf("%.2x", digest[t]);
    printf("  %s\n", argv[1]);

    free(digest);

    return EXIT_SUCCESS;
}
