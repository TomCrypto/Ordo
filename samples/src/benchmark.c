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
    size_t t, count;

    printf("Usage:\n\n"); 
    printf("\t%s [hash function]\n", argv[0]);
    printf("\t%s [stream cipher]\n", argv[0]);
    printf("\t%s [block cipher] [mode of operation]\n", argv[0]);

    printf("\nAvailable hash functions:\n\n\t");
    count = hash_function_count();
    for (t = 0; t < count; ++t)
    {
        printf("%s", hash_function_name(hash_function_by_index(t)));
        if (t != count - 1) printf(", "); else printf("\n");
    }

    printf("\nAvailable stream ciphers:\n\n\t");
    count = stream_cipher_count();
    for (t = 0; t < count; ++t)
    {
        printf("%s", stream_cipher_name(stream_cipher_by_index(t)));
        if (t != count - 1) printf(", "); else printf("\n");
    }

    printf("\nAvailable block ciphers:\n\n\t");
    count = block_cipher_count();
    for (t = 0; t < count; ++t)
    {
        printf("%s", block_cipher_name(block_cipher_by_index(t)));
        if (t != count - 1) printf(", "); else printf("\n");
    }

    printf("\nAvailable modes of operation:\n\n\t");
    count = block_mode_count();
    for (t = 0; t < count; ++t)
    {
        printf("%s", block_mode_name(block_mode_by_index(t)));
        if (t != count - 1) printf(", "); else printf("\n");
    }

}

/***                         TIME UTILITY FUNCTIONS                         ***/

#define INTERVAL 3.0

static double now()
{
    return (double)clock() / CLOCKS_PER_SEC;
}

static double speed_MiB(double processed)
{
    return processed / (INTERVAL * 1024 * 1024);
}

/***                        PARAMETERIZED UTILITIES                         ***/

static void *hash_params(const struct HASH_FUNCTION *hash)
{
    return 0;
}

static void *block_params(const struct BLOCK_CIPHER *cipher)
{
    return 0;
}

static void *block_mode_params(const struct BLOCK_MODE *mode)
{
    if (mode == ecb())
    {
        struct ECB_PARAMS *ecb = allocate(sizeof(*ecb));
        ecb->padding = 0;
        return ecb;
    }

    if (mode == cbc())
    {
        struct CBC_PARAMS *cbc = allocate(sizeof(*cbc));
        cbc->padding = 0;
        return cbc;
    }

    return 0;
}

static void *stream_params(const struct STREAM_CIPHER *cipher)
{
    if (cipher == rc4())
    {
        struct RC4_PARAMS *rc4 = allocate(sizeof(*rc4));
        rc4->drop = 0;
        return rc4;
    }

    return 0;
}

/***                          LOW-LEVEL BENCHMARKS                          ***/

static double hash_speed(const struct HASH_FUNCTION *hash,
                         uint64_t block)
{
    struct DIGEST_CTX *ctx = digest_alloc(hash);
    os_random(buffer, sizeof(buffer));

    if (ctx)
    {
        void *params = hash_params(hash);

        uint64_t iterations = 0;
        double start = now();

        while ((++iterations) && (now() - start < INTERVAL))
        {
            digest_init(ctx, params);
            digest_update(ctx, buffer, block);
            digest_final(ctx, buffer);
        }

        digest_free(ctx);
        free(params);

        return speed_MiB(block * iterations);
    }

    printf("\t* Context allocation failed!\n");
    printf("\nAn error occurred.\n");
    exit(EXIT_FAILURE);
}

static double stream_speed(const struct STREAM_CIPHER *cipher,
                           uint64_t block)
{
    struct ENC_STREAM_CTX *ctx = enc_stream_alloc(cipher);
    os_random(buffer, sizeof(buffer));

    if (ctx)
    {
        void *params = stream_params(cipher);

        size_t key_len = stream_cipher_query(cipher, KEY_LEN, (size_t)-1);
        
        void *key = allocate(key_len);

        uint64_t iterations = 0;
        double start = now();

        while ((++iterations) && (now() - start < INTERVAL))
        {
            enc_stream_init(ctx, key, key_len, params);
            enc_stream_update(ctx, buffer, block);
        }

        enc_stream_free(ctx);
        free(params);
        free(key);

        return speed_MiB(block * iterations);
    }

    printf("\t* Context allocation failed!\n");
    printf("\nAn error occurred.\n");
    exit(EXIT_FAILURE);
}

static double block_speed(const struct BLOCK_CIPHER *cipher,
                          const struct BLOCK_MODE *mode,
                          uint64_t block)
{
    struct ENC_BLOCK_CTX *ctx = enc_block_alloc(cipher, mode);
    os_random(buffer, sizeof(buffer));

    if (ctx)
    {
        void *cipher_params = block_params(cipher);
        void *mode_params = block_mode_params(mode);

        size_t key_len = block_cipher_query(cipher, KEY_LEN, (size_t)-1);
        size_t iv_len = block_mode_query(mode, cipher, IV_LEN, (size_t)-1);

        void *key = allocate(key_len);
        void *iv = allocate(iv_len);

        uint64_t iterations = 0;
        double start = now();

        while ((++iterations) && (now() - start < INTERVAL))
        {
            size_t out;
            enc_block_init(ctx, key, key_len, iv, iv_len,
                           1, cipher_params, mode_params);
            enc_block_update(ctx, buffer, block, buffer, &out);
            enc_block_final(ctx, buffer, &out);
        }

        enc_block_free(ctx);
        free(cipher_params);
        free(mode_params);
        free(key);
        free(iv);

        return speed_MiB(block * iterations);
    }

    printf("\t* Context allocation failed!\n");
    printf("\nAn error occurred.\n");
    exit(EXIT_FAILURE);
}

/***                          HIGH-LEVEL BENCHMARK                          ***/

static int benchmark_hash_function(const struct HASH_FUNCTION *hash,
                                   int argc, char * const argv[])
{
    const char *name = hash_function_name(hash);
    
    if (argc > 2)
    {
        printf("Unrecognized argument '%s'.\n", argv[2]);
        return EXIT_FAILURE;
    }
    
    printf("Benchmarking hash function %s:\n\n", name);
    printf("\t*    16 bytes: %4.0f MiB/s\n", hash_speed(hash,    16));
    printf("\t*   256 bytes: %4.0f MiB/s\n", hash_speed(hash,   256));
    printf("\t*  1024 bytes: %4.0f MiB/s\n", hash_speed(hash,  1024));
    printf("\t*  4096 bytes: %4.0f MiB/s\n", hash_speed(hash,  4096));
    printf("\t* 65536 bytes: %4.0f MiB/s\n", hash_speed(hash, 65536));
    printf("\nPerformance rated over %.2f seconds.\n", INTERVAL);

    return EXIT_SUCCESS;
}

static int benchmark_stream_cipher(const struct STREAM_CIPHER *cipher,
                                   int argc, char * const argv[])
{
    const char *name = stream_cipher_name(cipher);

    if (argc != 2)
    {
        printf("Unrecognized argument '%s'.\n", argv[2]);
        return EXIT_FAILURE;
    }

    printf("Benchmarking stream cipher %s:\n\n", name);
    printf("\t*    16 bytes: %4.0f MiB/s\n", stream_speed(cipher,    16));
    printf("\t*   256 bytes: %4.0f MiB/s\n", stream_speed(cipher,   256));
    printf("\t*  1024 bytes: %4.0f MiB/s\n", stream_speed(cipher,  1024));
    printf("\t*  4096 bytes: %4.0f MiB/s\n", stream_speed(cipher,  4096));
    printf("\t* 65536 bytes: %4.0f MiB/s\n", stream_speed(cipher, 65536));
    printf("\nPerformance rated over %.2f seconds.\n", INTERVAL);

    return EXIT_SUCCESS;
}

static int benchmark_block_cipher(const struct BLOCK_CIPHER *cipher,
                                   int argc, char * const argv[])
{
    const char *name = block_cipher_name(cipher);
    const struct BLOCK_MODE *mode;

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

    if (!(mode = block_mode_by_name(argv[2])))
    {
        printf("Unrecognized mode of operation '%s'.\n", argv[2]);
        return EXIT_FAILURE;
    }

    printf("Benchmarking block cipher %s in %s mode:\n\n", name, argv[2]);
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
    if (hash_function_by_name(name) != 0) return ALG_HASH;
    if (stream_cipher_by_name(name) != 0) return ALG_STREAM;
    if (block_cipher_by_name(name)  != 0) return ALG_BLOCK;
    return ALG_NONE;
}

/***                             MAIN DISPATCHER                            ***/

int main(int argc, char *argv[])
{
    if (ordo_init())
    {
        printf("Failed to initialize Ordo.\n");
        return EXIT_FAILURE;
    }

    if (argc < 2)
    {
        benchmark_usage(argc, argv);
        return EXIT_FAILURE;
    }

    switch (identify(argv[1]))
    {
        case ALG_HASH:
        {
            const struct HASH_FUNCTION *p = hash_function_by_name(argv[1]);
            return benchmark_hash_function(p, argc, argv);
        }

        case ALG_STREAM:
        {
            const struct STREAM_CIPHER *p = stream_cipher_by_name(argv[1]);
            return benchmark_stream_cipher(p, argc, argv);
        }

        case ALG_BLOCK:
        {
            const struct BLOCK_CIPHER *p = block_cipher_by_name(argv[1]);
            return benchmark_block_cipher(p, argc, argv);
        }

        case ALG_NONE:
        {
            printf("Unrecognized argument '%s'.\n", argv[1]);
            return EXIT_FAILURE;
        }
    }
    
    return EXIT_SUCCESS;
}
