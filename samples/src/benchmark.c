/* Sample: benchmark - benchmarks all algorithms provided by the library.
 * ------
 * Demonstrates:
 *  - enumerating algorithms
 *  - using the high-level API (no contexts are used here)
 * ------
 * Usage: benchmark [optional: buffer size in megabytes]
 * If no buffer size is provided, uses 128 megabytes by default.
 * ------
 * Comments: some of the code here is rather convoluted, this is because
 *           parameters are not part of the abstraction layer. In particular,
 *           padding is a block mode parameter and hence it is difficult to
 *           abstract it away. What is done instead is assume there is enough
 *           space to handle padding (by adding a few extra dummy bytes at
 *           the end of the buffer) which is good enough for benchmarking
 *           purposes.
 *           In a real application the mode of operation would be known in
 *           advance and parameters would be concretely passed and padding
 *           handled as it should be. Equivalently, we could do that here
 *           by manually implementing each and every algorithm, but this
 *           would lead to a lot of repeated code and would overall be
 *           worse than the alternative.
*/

#include <string.h>
#include <stdio.h>
#include <time.h>

#include "ordo.h"

#define BUF_SIZE (128 * 1024 * 1024)

/* This is a fast algorithm for randomizing a buffer. It is not included in the
 * timing calculations but is used to prevent the hardware optimizing things by
 * keeping the buffer in cache, which would skew the benchmark results. */
void randomize(void *buffer, size_t buf_size)
{
    /* OK fine, this is really using RC4 with a random key >.< */
    size_t key_len = 32;
    void *key = malloc(key_len);
    os_random(key, key_len);

    ordo_enc_stream(rc4(), 0, key, key_len, buffer, buf_size);
    free(key);
}

void benchmark_hash_functions(void *buffer, size_t buf_size)
{
    for (size_t id = 0; id < hash_function_count(); ++id)
    {
        const struct HASH_FUNCTION *primitive = hash_function_by_id(id);
        printf(" * %.20s: \t", hash_function_name(primitive));
        fflush(stdout);

        randomize(buffer, buf_size);

        clock_t start = clock();

        ordo_digest(primitive, 0, /* No parameters. */
                    buffer, buf_size,
                    buffer); /* For simplicity, write output in buffer. */

        double time = (double)(clock() - start) / (double)CLOCKS_PER_SEC;
        double speed = buf_size / (1024 * 1024 * time);

        printf("%.0f MB/s.\n", speed);
    }

    printf(" -\n\n");
}

void benchmark_block_ciphers(void *buffer, size_t buf_size)
{
    for (size_t id = 0; id < block_cipher_count(); ++id)
    {
        const struct BLOCK_CIPHER *primitive = block_cipher_by_id(id);

        /* Probe cipher's smallest key length. */
        size_t key_len = enc_block_key_len(primitive, 0);
        void *key = malloc(key_len);

        for (size_t mode_id = 0; mode_id < block_mode_count(); ++mode_id)
        {
            const struct BLOCK_MODE *mode = block_mode_by_id(mode_id);
            size_t iv_len = enc_block_iv_len(primitive, mode, -1);
            void *iv = malloc(iv_len);
            
            printf(" * %.20s [%.10s]: \t", block_cipher_name(primitive),
                                           block_mode_name(mode));
            fflush(stdout);

            os_random(iv, iv_len);
            os_random(key, key_len);
            randomize(buffer, buf_size);

            clock_t start = clock();

            /* Encryption */
            size_t out_len = 0;
            ordo_enc_block(primitive, 0, mode, 0,
                           1,
                           key,
                           key_len,
                           iv,
                           iv_len,
                           buffer, buf_size,
                           buffer, &out_len); /* Encrypt in-place */

            double time = (double)(clock() - start) / (double)CLOCKS_PER_SEC;
            double speed = buf_size / (1024 * 1024 * time);

            printf("%.0f MB/s (enc)\t|\t", speed);
            fflush(stdout);

            os_random(iv, iv_len);
            os_random(key, key_len);
            randomize(buffer, out_len);

            start = clock();

            /* Decryption */
            ordo_enc_block(primitive, 0, mode, 0,
                           0,
                           key,
                           key_len,
                           iv,
                           iv_len,
                           buffer, out_len,
                           buffer, &out_len);

            time = (double)(clock() - start) / (double)CLOCKS_PER_SEC;
            speed = buf_size / (1024 * 1024 * time);

            printf("%.0f MB/s (dec) ", speed);
            printf("\t[%d-bit key]\n", (int)key_len * 8);
            free(iv);
        }

        free(key);
        if (id != block_cipher_count() - 1) printf(" &\n");
    }

    printf(" -\n\n");
}


void benchmark_stream_ciphers(void *buffer, size_t buf_size)
{
    for (size_t id = 0; id < stream_cipher_count(); ++id)
    {
        const struct STREAM_CIPHER *primitive = stream_cipher_by_id(id);
        printf(" * %.20s: \t", stream_cipher_name(primitive));
        fflush(stdout);

        randomize(buffer, buf_size);

        clock_t start = clock();

        /* Probe the stream cipher for the smallest key length (we are not
         * benchmarking the key schedule, and encryption speed is normally
         * independent from key size). */
        size_t key_len = enc_stream_key_len(primitive, 0);
        void *key = malloc(key_len);
        os_random(key, key_len);

        ordo_enc_stream(primitive, 0, key, key_len, buffer, buf_size);
        free(key);

        double time = (double)(clock() - start) / (double)CLOCKS_PER_SEC;
        double speed = buf_size / (1024 * 1024 * time);

        printf("%.0f MB/s\t[%d-bit key].\n", speed, (int)key_len * 8);
    }

    printf(" -\n\n");
}

void benchmark_pbkdf2(void *buffer, size_t buf_size, size_t iterations)
{
    for (size_t id = 0; id < hash_function_count(); ++id)
    {
        const struct HASH_FUNCTION *primitive = hash_function_by_id(id);
        printf(" * PBKDF2 [%.10s]: \t", hash_function_name(primitive));
        fflush(stdout);

        /* We only want to benchmark one "block" of PBKDF2, so feed it only
         * one byte by convention. */
        buf_size = 1;

        clock_t start = clock();

        pbkdf2(primitive, 0,
               buffer, buf_size,
               buffer, buf_size,
               iterations,
               buffer, buf_size); 

        double time = (double)(clock() - start) / (double)CLOCKS_PER_SEC;

        printf("%.1f s.\n", time);
    }

    printf(" -\n\n");
}

int main(int argc, char *argv[])
{
    if (argc > 2)
    {
        printf("Usage: benchmark [optional: buffer size in megabytes]\n");
        return EXIT_FAILURE;
    }

    if (ordo_init())
    {
        printf("Failed to initialize Ordo.\n");
        return EXIT_FAILURE;
    }

    size_t buf_size = (argc == 2 ? atoi(argv[1]) : 128);
    buf_size *= 1024 * 1024; /* To MB */

    /* Add a megabyte of padding for algorithms which use padding, to make
     * sure they don't fail (this is a bit ugly but sufficient for what we 
     * are doing here, see comments at top of source file). */
    void *buffer = malloc(buf_size + 1024 * 1024);
    memset(buffer, 0x00, buf_size + 1024 * 1024);

    printf("Benchmarking: Hash Functions\n");
    printf("----------------------------\n\n");
    benchmark_hash_functions(buffer, buf_size);

    printf("Benchmarking: Block Ciphers\n");
    printf("---------------------------\n\n");
    benchmark_block_ciphers(buffer, buf_size);

    printf("Benchmarking: Stream Ciphers\n");
    printf("----------------------------\n\n");
    benchmark_stream_ciphers(buffer, buf_size);

    printf("Benchmarking: PBKDF2 (100000 iterations)\n");
    printf("----------------------------------------\n\n");
    benchmark_pbkdf2(buffer, buf_size, 100000);


    free(buffer);
    return EXIT_SUCCESS;
}
