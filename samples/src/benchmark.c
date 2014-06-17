/* Sample: benchmark - benchmarks all algorithms provided by the library.
 * ------
 * Demonstrates:
 *  - enumerating algorithms
 *  - querying information about algorithms (key/IV length, etc..)
 * ------
 * Usage: see benchmark_usage() below, or run with no arguments.
 * ------
 * Comments: note that some of the benchmarked algorithms do have specific
 *           parameters set, see the *_params() functions, and can be done
 *           on a per-algorithm basis rather elegantly - for instance here
 *           it is used to disable RC4 drop (so as not to skew small block
 *           size timings) and ECB/CBC padding. Furthermore, for the block
 *           cipher algorithms, only encryption is currently benchmarked.
*/

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#include "ordo.h"

/***                         DATA STORAGE BUFFER                            ***/

#define MAX_BLOCK_SIZE 65536

static char buffer[MAX_BLOCK_SIZE];

/***                    MISCELLANEOUS UTILITY FUNCTIONS                     ***/

static void *allocate(size_t size)
{
    void *ptr = malloc(size);
    if (ptr)
    {
        os_random(ptr, size);
        return ptr;
    }

    printf("\t* Memory allocation failed!\n");
    printf("\nAn error occurred.\n");
    exit(EXIT_FAILURE);
}

static void benchmark_usage(int argc, char * const argv[])
{
    const int *p;

    printf("Usage:\n\n");
    printf("\t%s [hash function]\n", argv[0]);
    printf("\t%s [stream cipher]\n", argv[0]);
    printf("\t%s [block cipher] [mode of operation]\n", argv[0]);

    printf("\nAvailable hash functions:\n\n\t");
    for (p = prim_from_type(PRIM_TYPE_HASH); *p; ++p)
    {
        printf("%s", prim_name(*p));
        if (*(p + 1)) printf(", "); else printf("\n");
    }

    printf("\nAvailable stream ciphers:\n\n\t");
    for (p = prim_from_type(PRIM_TYPE_STREAM); *p; ++p)
    {
        printf("%s", prim_name(*p));
        if (*(p + 1)) printf(", "); else printf("\n");
    }

    printf("\nAvailable block ciphers:\n\n\t");
    for (p = prim_from_type(PRIM_TYPE_BLOCK); *p; ++p)
    {
        printf("%s", prim_name(*p));
        if (*(p + 1)) printf(", "); else printf("\n");
    }

    printf("\nAvailable modes of operation:\n\n\t");
    for (p = prim_from_type(PRIM_TYPE_BLOCK_MODE); *p; ++p)
    {
        printf("%s", prim_name(*p));
        if (*(p + 1)) printf(", "); else printf("\n");
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
typedef double my_time;

static my_time now()
{
    return (double)clock() / CLOCKS_PER_SEC;
}

static double get_elapsed(my_time start)
{
    return now() - start;
}
#endif

static double speed_MiB(uint64_t throughput, double elapsed)
{
    return ((double)throughput / (1024 * 1024)) / elapsed;
}

/***                        PARAMETERIZED UTILITIES                         ***/

static void *hash_params(int hash)
{
    return 0;
}

static void *block_params(int cipher)
{
    return 0;
}

static void *block_mode_params(int mode)
{
    if (mode == BLOCK_MODE_ECB)
    {
        struct ECB_PARAMS *ecb = allocate(sizeof(*ecb));
        ecb->padding = 0;
        return ecb;
    }

    if (mode == BLOCK_MODE_CBC)
    {
        struct CBC_PARAMS *cbc = allocate(sizeof(*cbc));
        cbc->padding = 0;
        return cbc;
    }

    return 0;
}

static void *stream_params(int cipher)
{
    if (cipher == STREAM_RC4)
    {
        /* we don't want to benchmark dropping bytes of RC4
         * as this would heavily penalize the short blocks. */
        struct RC4_PARAMS *rc4 = allocate(sizeof(*rc4));
        rc4->drop = 0;
        return rc4;
    }

    return 0;
}

/***                          LOW-LEVEL BENCHMARKS                          ***/

static double hash_speed(int hash, uint64_t block)
{
    os_random(buffer, sizeof(buffer));

    {
        void *params = hash_params(hash);
        struct DIGEST_CTX ctx;

        uint64_t iterations = 0;
        double elapsed;
        my_time start;

        digest_init(&ctx, hash, params);

        start = now();

        while (++iterations && (get_elapsed(start) < INTERVAL))
            digest_update(&ctx, buffer, block);

        elapsed = get_elapsed(start);

        digest_final(&ctx, buffer);
        free(params);

        return speed_MiB(block * iterations, elapsed);
    }
}

static double stream_speed(int cipher, uint64_t block)
{
    os_random(buffer, sizeof(buffer));

    {
        void *params = stream_params(cipher);
        struct ENC_STREAM_CTX ctx;

        size_t key_len = stream_cipher_query(cipher, KEY_LEN_Q, (size_t)-1);

        void *key = allocate(key_len);

        uint64_t iterations = 0;
        double elapsed;
        my_time start;

        enc_stream_init(&ctx, key, key_len, cipher, params);

        start = now();

        while (++iterations && (get_elapsed(start) < INTERVAL))
            enc_stream_update(&ctx, buffer, block);

        elapsed = get_elapsed(start);

        enc_stream_final(&ctx);
        free(params);
        free(key);

        return speed_MiB(block * iterations, elapsed);
    }
}

static double block_speed(int cipher, int mode, uint64_t block)
{
    os_random(buffer, sizeof(buffer));

    {
        void *cipher_params = block_params(cipher);
        void *mode_params = block_mode_params(mode);
        struct ENC_BLOCK_CTX ctx;

        size_t key_len = block_cipher_query(cipher, KEY_LEN_Q, (size_t)-1);
        size_t iv_len = block_mode_query(mode, cipher, IV_LEN_Q, (size_t)-1);

        void *key = allocate(key_len);
        void *iv = allocate(iv_len);

        uint64_t iterations = 0;
        double elapsed;
        my_time start;
        size_t out;

        enc_block_init(&ctx, key, key_len, iv, iv_len,
                       1, cipher, cipher_params, mode, mode_params);

        start = now();

        while (++iterations && (get_elapsed(start) < INTERVAL))
            enc_block_update(&ctx, buffer, block, buffer, &out);

        elapsed = get_elapsed(start);

        enc_block_final(&ctx, buffer, &out);
        free(cipher_params);
        free(mode_params);
        free(key);
        free(iv);

        return speed_MiB(block * iterations, elapsed);
    }
}

/***                          HIGH-LEVEL BENCHMARK                          ***/

static int benchmark_hash_function(int hash, int argc, char * const argv[])
{
    if (argc > 2)
    {
        printf("Unrecognized argument '%s'.\n", argv[2]);
        return EXIT_FAILURE;
    }

    printf("Benchmarking hash function %s:\n\n", argv[1]);
    printf("\t*    16 bytes: %4.0f MiB/s\n", hash_speed(hash,    16));
    printf("\t*   256 bytes: %4.0f MiB/s\n", hash_speed(hash,   256));
    printf("\t*  1024 bytes: %4.0f MiB/s\n", hash_speed(hash,  1024));
    printf("\t*  4096 bytes: %4.0f MiB/s\n", hash_speed(hash,  4096));
    printf("\t* 65536 bytes: %4.0f MiB/s\n", hash_speed(hash, 65536));
    printf("\nPerformance rated over %.2f seconds.\n", INTERVAL);

    return EXIT_SUCCESS;
}

static int benchmark_stream_cipher(int cipher, int argc, char * const argv[])
{
    if (argc != 2)
    {
        printf("Unrecognized argument '%s'.\n", argv[2]);
        return EXIT_FAILURE;
    }

    printf("Benchmarking stream cipher %s:\n\n", argv[1]);
    printf("\t*    16 bytes: %4.0f MiB/s\n", stream_speed(cipher,    16));
    printf("\t*   256 bytes: %4.0f MiB/s\n", stream_speed(cipher,   256));
    printf("\t*  1024 bytes: %4.0f MiB/s\n", stream_speed(cipher,  1024));
    printf("\t*  4096 bytes: %4.0f MiB/s\n", stream_speed(cipher,  4096));
    printf("\t* 65536 bytes: %4.0f MiB/s\n", stream_speed(cipher, 65536));
    printf("\nPerformance rated over %.2f seconds.\n", INTERVAL);

    return EXIT_SUCCESS;
}

static int benchmark_block_cipher(int cipher, int argc, char * const argv[])
{
    int mode;

    if (argc == 2)
    {
        printf("Please specify one mode of operation.\n");
        return EXIT_FAILURE;
    }

    if (argc > 3)
    {
        printf("Please specify only one mode of operation.\n");
        return EXIT_FAILURE;
    }

    mode = prim_from_name(argv[2]);

    if (prim_type(mode) != PRIM_TYPE_BLOCK_MODE)
    {
        printf("Unrecognized mode of operation '%s'.\n", argv[2]);
        return EXIT_FAILURE;
    }

    printf("Benchmarking block cipher %s in %s mode:\n\n", argv[1], argv[2]);
    printf("\t*    16 bytes: %4.0f MiB/s\n", block_speed(cipher, mode,    16));
    printf("\t*   256 bytes: %4.0f MiB/s\n", block_speed(cipher, mode,   256));
    printf("\t*  1024 bytes: %4.0f MiB/s\n", block_speed(cipher, mode,  1024));
    printf("\t*  4096 bytes: %4.0f MiB/s\n", block_speed(cipher, mode,  4096));
    printf("\t* 65536 bytes: %4.0f MiB/s\n", block_speed(cipher, mode, 65536));
    printf("\nPerformance rated over %.2f seconds.\n", INTERVAL);

    return EXIT_SUCCESS;
}

/***                        ALGORITHM IDENTIFICATION                        ***/

enum ALG_TYPE { ALG_NONE, ALG_HASH, ALG_STREAM, ALG_BLOCK };

static enum ALG_TYPE identify(const char *name)
{
    switch (prim_type(prim_from_name(name)))
    {
        case PRIM_TYPE_HASH:             return ALG_HASH;
        case PRIM_TYPE_STREAM:           return ALG_STREAM;
        case PRIM_TYPE_BLOCK:            return ALG_BLOCK;
    }

    return ALG_NONE;
}

/***                             MAIN DISPATCHER                            ***/

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        benchmark_usage(argc, argv);
        return EXIT_FAILURE;
    }

    switch (identify(argv[1]))
    {
        case ALG_HASH:
            return benchmark_hash_function(prim_from_name(argv[1]), argc, argv);
        case ALG_STREAM:
            return benchmark_stream_cipher(prim_from_name(argv[1]), argc, argv);
        case ALG_BLOCK:
            return benchmark_block_cipher(prim_from_name(argv[1]), argc, argv);
        case ALG_NONE:
        {
            printf("Unrecognized argument '%s'.\n", argv[1]);
            return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}
