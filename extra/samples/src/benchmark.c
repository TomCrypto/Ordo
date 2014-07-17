/*===-- samples/benchmark.c ----------------------------*- PUBLIC -*- C -*-===*/
/**
*** @file
*** @brief Sample
***
*** This sample will benchmark a given primitive provided on the command-line,
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
#include <time.h>

#include "ordo.h"

/*===--------------------------- SCRATCH BUFFER ---------------------------===*/

static char buffer[65536];

/*===------------------- MISCELLANEOUS UTILITY FUNCTIONS ------------------===*/

/* Yes, the infamous xmalloc. Just to allocate a few bytes to hold key/IV and
 * primitive parameter data (which is fairly dynamic). */
static void *xmalloc(size_t size)
{
    void *ptr = malloc(size);

    if (!ptr)
    {
        printf("\t* Memory allocation failed!\n");
        printf("\nAn error occurred.\n");
        exit(EXIT_FAILURE);
    }

    return ptr;
}

static void print_usage(int argc, char * const argv[])
{
    const prim_t *p;

    printf("Usage:\n\n");
    printf("\t%s [hash function]\n", argv[0]);
    printf("\t%s [stream cipher]\n", argv[0]);
    printf("\t%s [block cipher]\n", argv[0]);
    printf("\t%s [block cipher] [mode of operation]\n", argv[0]);

    printf("\nAvailable hash functions:\n\n\t");
    for (p = prims_by_type(PRIM_TYPE_HASH); *p; ++p)
    {
        printf("%s", prim_name(*p));
        if (*(p + 1)) printf(", ");
        else printf("\n");
    }

    printf("\nAvailable stream ciphers:\n\n\t");
    for (p = prims_by_type(PRIM_TYPE_STREAM); *p; ++p)
    {
        printf("%s", prim_name(*p));
        if (*(p + 1)) printf(", ");
        else printf("\n");
    }

    printf("\nAvailable block ciphers:\n\n\t");
    for (p = prims_by_type(PRIM_TYPE_BLOCK); *p; ++p)
    {
        printf("%s", prim_name(*p));
        if (*(p + 1)) printf(", ");
        else printf("\n");
    }

    printf("\nAvailable modes of operation:\n\n\t");
    for (p = prims_by_type(PRIM_TYPE_BLOCK_MODE); *p; ++p)
    {
        printf("%s", prim_name(*p));
        if (*(p + 1)) printf(", ");
        else printf("\n");
    }
}

/***                         TIME UTILITY FUNCTIONS                         ***/

#define INTERVAL 3.0 /* seconds */

#if defined(_WIN32) || defined(_WIN64)
typedef int64_t my_time;
#include <windows.h>

static my_time now()
{
    LARGE_INTEGER t;
    QueryPerformanceCounter(&t);
    return t.QuadPart;
}

static double get_elapsed(my_time start)
{
    LARGE_INTEGER t, f;
    QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&t);

    return (double)(t.QuadPart - start) / f.QuadPart;
}
#else
typedef uintmax_t my_time;

static my_time now()
{
    return (my_time)clock();
}

static double get_elapsed(my_time start)
{
    return (now() - start) / (double)CLOCKS_PER_SEC;
}
#endif

static double speed_MiB(uint64_t throughput, double elapsed)
{
    return ((double)throughput / (1024 * 1024)) / elapsed;
}

/*===---------------------- PRIMITIVE PARAMETER SETUP ---------------------===*/

static void *hash_params(prim_t hash)
{
    return 0;
}

static void *block_params(prim_t cipher)
{
    return 0;
}

static void *block_mode_params(prim_t mode)
{
    if (mode == BLOCK_MODE_ECB)
    {
        struct ECB_PARAMS *ecb = xmalloc(sizeof(*ecb));
        ecb->padding = 0;
        return ecb;
    }

    if (mode == BLOCK_MODE_CBC)
    {
        struct CBC_PARAMS *cbc = xmalloc(sizeof(*cbc));
        cbc->padding = 0;
        return cbc;
    }

    return 0;
}

static void *stream_params(prim_t cipher)
{
    if (cipher == STREAM_RC4)
    {
        /* We don't want to benchmark dropping bytes of RC4
         * as this would heavily penalize the short blocks.
        */
        struct RC4_PARAMS *rc4 = xmalloc(sizeof(*rc4));
        rc4->drop = 0;
        return rc4;
    }

    return 0;
}

/***                          LOW-LEVEL BENCHMARKS                          ***/

static double hash_speed(prim_t hash, uint64_t block)
{
    void *params = hash_params(hash);
    struct DIGEST_CTX ctx;

    uint64_t iterations = 0;
    double elapsed;
    my_time start;

    digest_init(&ctx, hash, params);

    start = now();

    while (++iterations && (get_elapsed(start) < INTERVAL))
        digest_update(&ctx, buffer, (size_t)block);

    elapsed = get_elapsed(start);

    digest_final(&ctx, buffer);
    free(params);

    return speed_MiB(block * iterations, elapsed);
}

static double stream_speed(prim_t cipher, uint64_t block)
{
    void *params = stream_params(cipher);
    struct ENC_STREAM_CTX ctx;

    size_t key_len = enc_stream_key_len(cipher, (size_t)-1);

    void *key = xmalloc(key_len);

    uint64_t iterations = 0;
    double elapsed;
    my_time start;

    enc_stream_init(&ctx, key, key_len, cipher, params);

    start = now();

    while (++iterations && (get_elapsed(start) < INTERVAL))
        enc_stream_update(&ctx, buffer, (size_t)block);

    elapsed = get_elapsed(start);

    enc_stream_final(&ctx);
    free(params);
    free(key);

    return speed_MiB(block * iterations, elapsed);
}

static double block_speed(prim_t cipher, prim_t mode, uint64_t block)
{
    void *cipher_params = block_params(cipher);
    void *mode_params = block_mode_params(mode);
    struct ENC_BLOCK_CTX ctx;

    size_t key_len = block_query(cipher, KEY_LEN_Q, (size_t)-1);
    size_t iv_len = block_mode_query(mode, cipher, IV_LEN_Q, (size_t)-1);

    void *key = xmalloc(key_len);
    void *iv = xmalloc(iv_len);

    uint64_t iterations = 0;
    double elapsed;
    my_time start;
    size_t out;

    enc_block_init(&ctx, key, key_len, iv, iv_len,
                   1, cipher, cipher_params, mode, mode_params);

    start = now();

    while (++iterations && (get_elapsed(start) < INTERVAL))
        enc_block_update(&ctx, buffer, (size_t)block, buffer, &out);

    elapsed = get_elapsed(start);

    enc_block_final(&ctx, buffer, &out);
    free(cipher_params);
    free(mode_params);
    free(key);
    free(iv);

    return speed_MiB(block * iterations, elapsed);
}

/*===-------------------- HIGH LEVEL BENCHMARK ROUTINES -------------------===*/

static int bench_hash(prim_t hash, int argc, char * const argv[])
{
    if (argc > 2)
        return printf("Unrecognized argument '%s'.\n", argv[2]), EXIT_FAILURE;

    printf("Benchmarking hash function %s:\n\n", argv[1]);
    printf("\t*    16 bytes: %4.0f MiB/s\n", hash_speed(hash,    16));
    printf("\t*   256 bytes: %4.0f MiB/s\n", hash_speed(hash,   256));
    printf("\t*  1024 bytes: %4.0f MiB/s\n", hash_speed(hash,  1024));
    printf("\t*  4096 bytes: %4.0f MiB/s\n", hash_speed(hash,  4096));
    printf("\t* 65536 bytes: %4.0f MiB/s\n", hash_speed(hash, 65536));
    printf("\nPerformance rated over %.2f seconds.\n", INTERVAL);

    return EXIT_SUCCESS;
}

static int bench_stream(prim_t cipher, int argc, char * const argv[])
{
    if (argc > 2)
        return printf("Unrecognized argument '%s'.\n", argv[2]), EXIT_FAILURE;

    printf("Benchmarking stream cipher %s:\n\n", argv[1]);
    printf("\t*    16 bytes: %4.0f MiB/s\n", stream_speed(cipher,    16));
    printf("\t*   256 bytes: %4.0f MiB/s\n", stream_speed(cipher,   256));
    printf("\t*  1024 bytes: %4.0f MiB/s\n", stream_speed(cipher,  1024));
    printf("\t*  4096 bytes: %4.0f MiB/s\n", stream_speed(cipher,  4096));
    printf("\t* 65536 bytes: %4.0f MiB/s\n", stream_speed(cipher, 65536));
    printf("\nPerformance rated over %.2f seconds.\n", INTERVAL);

    return EXIT_SUCCESS;
}

static int bench_block(prim_t cipher, int argc, char * const argv[])
{
    prim_t mode;

    if (argc == 2)
        return printf("Please specify one mode.\n"), EXIT_FAILURE;

    if (argc > 3)
        return printf("Please specify only one mode.\n"), EXIT_FAILURE;

    mode = prim_from_name(argv[2]);

    if (!mode || (prim_type(mode) != PRIM_TYPE_BLOCK_MODE))
        return printf("Unrecognized argument '%s'.\n", argv[2]), EXIT_FAILURE;

    printf("Benchmarking block cipher %s in %s mode:\n\n", argv[1], argv[2]);
    printf("\t*    16 bytes: %4.0f MiB/s\n", block_speed(cipher, mode,    16));
    printf("\t*   256 bytes: %4.0f MiB/s\n", block_speed(cipher, mode,   256));
    printf("\t*  1024 bytes: %4.0f MiB/s\n", block_speed(cipher, mode,  1024));
    printf("\t*  4096 bytes: %4.0f MiB/s\n", block_speed(cipher, mode,  4096));
    printf("\t* 65536 bytes: %4.0f MiB/s\n", block_speed(cipher, mode, 65536));
    printf("\nPerformance rated over %.2f seconds.\n", INTERVAL);

    return EXIT_SUCCESS;
}

/*===-------------------- MAIN FUNCTION AND DISPATCHER --------------------===*/

int main(int argc, char *argv[])
{
    prim_t primitive;

    if (argc < 2) return print_usage(argc, argv), EXIT_FAILURE;
    primitive = prim_from_name(argv[1]); /* Parse primitive. */

    switch (prim_type(primitive))
    {
        case PRIM_TYPE_HASH:
            return bench_hash(primitive, argc, argv);
        case PRIM_TYPE_STREAM:
            return bench_stream(primitive, argc, argv);
        case PRIM_TYPE_BLOCK:
            return bench_block(primitive, argc, argv);
        default:
            printf("Unrecognized argument `%s`.\n", argv[1]);
            return EXIT_FAILURE;
    }
}
