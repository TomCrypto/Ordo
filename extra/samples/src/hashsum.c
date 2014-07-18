/*===-- hashsum.c --------------------------------------*- SAMPLE -*- C -*-===*/
/**
*** @file
*** @brief Sample
***
*** This sample will take a list of files on the command-line and output their
*** digest given some hash function - this hash function used can be specified
*** via `--algorithm` or `-a` and is defined to be MD5 by default.
***
*** Shows how to use the (context-based) digest API, and also how to work with
*** prim_t primitive types, specifically, parsing them and checking types.
***
*** Usage:
***         ./hashsum [--algorithm MD5/SHA-256/etc] [FILE ...]
**/
/*===----------------------------------------------------------------------===*/

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "ordo.h"

static int process_file(const char *path, prim_t prim)
{
    /* The HASH_DIGEST_LEN quantity (see ordo/definitions.h) is defined as the
     * maximum digest length of all available hash functions which are in this
     * version of the library. This is used mainly for stack allocation of the
     * internal data structures, but you are free to use it yourself, to avoid
     * heap allocation. It is, of course, completely optional to use it - thus
     * you could malloc if you wanted to (or needed to be binary-compatible).
    */
    unsigned char digest[HASH_DIGEST_LEN];
    FILE *file = fopen(path, "rb");
    struct DIGEST_CTX ctx;
    size_t t;

    if (digest_init(&ctx, prim, 0))
        return 0;

    if (!file)
    {
        perror(path);
        return 0;
    }

    while (1)
    {
        unsigned char buf[4096]; /* Read in chunks. */
        size_t len = fread(buf, 1, sizeof(buf), file);

        if (!len)
        {
            if (!feof(file))
            {
                perror(path);
                fclose(file);
                return 0;
            }

            break;
        }

        digest_update(&ctx, buf, len);
    }

    fclose(file);

    digest_final(&ctx, digest);

    for (t = 0; t < digest_length(prim); ++t)
        printf("%.2x", digest[t]);
    printf("  %s\n", path);

    return 1;
}

static void usage(const char *prog)
{
    printf("Usage:\n\t%s [--algorithm MD5/SHA-256/etc] [FILE ...]\n", prog);
}

int main(int argc, char *argv[])
{
    /* Default algorithm */
    prim_t prim = HASH_MD5;

    if (argc == 1)
        return usage(argv[0]), EXIT_SUCCESS;

    if (!strcmp(argv[1], "-a") || !strcmp(argv[1], "--algorithm"))
    {
        if (argc == 2)
            return usage(argv[0]), EXIT_FAILURE;

        prim = prim_from_name(argv[2]);

        if (!prim || (prim_type(prim) != PRIM_TYPE_HASH))
        {
            printf("Invalid hash function `%s`.\n", argv[2]);
            return EXIT_FAILURE;
        }

        argv += 2; /* Skip options */
    }

    while (*++argv) /* Immediately stop on the 1st error. */
        if (!process_file(*argv, prim)) return EXIT_FAILURE;

    return EXIT_SUCCESS;
}
