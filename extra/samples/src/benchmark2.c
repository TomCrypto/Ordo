/*===-- samples/benchmark.c ----------------------------*- PUBLIC -*- C -*-===*/
/**
*** @file
*** @brief Sample
***
*** This sample will benchmark a given primitive provided via the command-line
*** printing the time taken to process a specific amount of data under various
*** conditions (for instance, varying the input buffer size, to study how much
*** overhead is present in the library API).
***
*** Shows how to enumerate algorithms, and how to use most of the library.
***
*** Usage:
***         ./benchmark [hash function]
***         ./benchmark [stream cipher]
***         ./benchmark [block cipher]
***         ./benchmark [block cipher] [mode of operation]
**/
/*===----------------------------------------------------------------------===*/

#include <stdlib.h>
#include <stdio.h>

#include "ordo.h"

/*===----------------------------------------------------------------------===*/

/* The parameter-related functions below work as follows: they are first given
 * a (stack-allocated!) polymorphic parameter union, and then do either of two
 * things depending on whether there is anything special to add as parameter:
 *
 * - fill in the union depending on the primitive, and return params
 * - nothing (i.e. default behaviour is desired), and return zero
 *
 * Then they can easily be used directly like this:
 *
 *     union xxx_PARAMS params;
 *     ...
 *     if (ordo_xxx(prim, xxx_params(prim, &params))) { ... }
*/

static union BLOCK_PARAMS *block_params(
    prim_t prim, union BLOCK_PARAMS *params)
{
    return 0;
}

static union STREAM_PARAMS *stream_params(
    prim_t prim, union STREAM_PARAMS *params)
{
    switch (prim)
    {
        case STREAM_RC4:
            params->rc4.drop = 0;
            return params;
    }

    return 0;
}

static union HASH_PARAMS *hash_params(
    prim_t prim, union HASH_PARAMS *params)
{
    return 0;
}

static union BLOCK_MODE_PARAMS *block_mode_params(
    prim_t prim, union BLOCK_MODE_PARAMS *params)
{
    switch (prim)
    {
        case BLOCK_MODE_ECB:
            params->ecb.padding = 0;
            return params;
        case BLOCK_MODE_CBC:
            params->cbc.padding = 0;
            return params;
    }

    return 0;
}

/*===----------------------------------------------------------------------===*/

#include <time.h>

/* TODO: timing routines? (callback?) */

/*===----------------------------------------------------------------------===*/

/* TODO: low level benchmark code? */

/*===----------------------------------------------------------------------===*/

/* TODO: high level benchmark code? */

/*===----------------------------------------------------------------------===*/

static void print_prim_list(const char *type_name, enum PRIM_TYPE type)
{
    const prim_t *p;

    printf("\nAvailable %s:\n\n\t", type_name);
    for (p = prims_by_type(type); *p; ++p)
    {
        printf("%s", prim_name(*p));
        if (*(p + 1)) printf(", ");
        else printf("\n");
    }
}

static void print_usage(const char *argv0)
{
    printf("Usage:\n\n");
    printf("\t%s [hash function]\n", argv0);
    printf("\t%s [stream cipher]\n", argv0);
    printf("\t%s [block cipher]\n", argv0);
    printf("\t%s [block cipher] [mode of operation]\n", argv0);

    print_prim_list("block ciphers", PRIM_TYPE_BLOCK);
    print_prim_list("stream ciphers", PRIM_TYPE_STREAM);
    print_prim_list("hash functions", PRIM_TYPE_HASH);
    print_prim_list("modes of operation", PRIM_TYPE_BLOCK_MODE);
}

int main(int argc, char *argv[])
{
    prim_t primitive;

    if (argc < 2) return print_usage(argv[0]), EXIT_FAILURE;
    primitive = prim_from_name(argv[1]); /* To benchmark. */

    switch (prim_type(primitive))
    {
    /*    case PRIM_TYPE_HASH:
            return bench_hash(primitive, argc, argv);
        case PRIM_TYPE_STREAM:
            return bench_stream(primitive, argc, argv);
        case PRIM_TYPE_BLOCK:
            return bench_block(primitive, argc, argv);*/
        default:
            printf("Unrecognized argument `%s`.\n", argv[1]);
            return EXIT_FAILURE;
    }
}
