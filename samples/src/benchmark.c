/*===-- benchmark.c ------------------------------------*- SAMPLE -*- C -*-===*/
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
***
***     ./benchmark [CMD ...]
***
*** For instance, passing a hash function benchmarks it, while passing a block
*** cipher alone will benchmark its forward permutation, while passing a block
*** cipher with a mode of operation benchmarks encryption in that mode, etc...
***
*** Example commands:
***
***     ./benchmark SHA-256
***     ./benchmark AES/CTR
***     ./benchmark AES
**/
/*===----------------------------------------------------------------------===*/

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "ordo.h"

#include "timer.h"

/*===----------------------------------------------------------------------===*/

/* The functions below are used for parsing - the ACTION enum determines which
 * operation will be benchmarked, while the different RECORD structs will hold
 * information about how to benchmark it, e.g. what primitive. The last struct
 * consists of a polymorphic union, as usual, with a short name ("m"). */

enum ACTION
{
    ACTION_BLOCK,
    ACTION_STREAM,
    ACTION_HASH,
    ACTION_BLOCK_MODE
};

/* No special parameters here yet, but it is now easy to add more. */

struct BLOCK_RECORD
{
    prim_t prim;
};

struct STREAM_RECORD
{
    prim_t prim;
};

struct HASH_RECORD
{
    prim_t prim;
};

struct BLOCK_MODE_RECORD
{
    prim_t prim, mode;
};

struct RECORD
{
    enum ACTION action;

    union
    {
        struct BLOCK_RECORD block;
        struct STREAM_RECORD stream;
        struct HASH_RECORD hash;
        struct BLOCK_MODE_RECORD block_mode;
    } m;
};

/*===----------------------------------------------------------------------===*/

static char *last_token;

static char *next_token(char **str)
{
    last_token = *str;

    if (*str)
    {
        char *delim = strstr(*str, "/");
        *str = delim ? delim + 1 : 0;
        if (delim) *delim = '\0';
    }

    return last_token;
}

static void rewind_token(char **str)
{
    *str = last_token;
}

static int parse_cmd(char **cmd, struct RECORD *rec)
{
    prim_t prim = prim_from_name(next_token(cmd));

    switch (prim_type(prim))
    {
        case PRIM_TYPE_HASH:
            rec->action = ACTION_HASH;
            rec->m.hash.prim = prim;
            break;
        case PRIM_TYPE_STREAM:
            rec->action = ACTION_STREAM;
            rec->m.stream.prim = prim;
            break;
        case PRIM_TYPE_BLOCK:
            if (!*cmd)
            {
                rec->action = ACTION_BLOCK;
                rec->m.block.prim = prim;
                break;
            }
            else
            {
                prim_t mode = prim_from_name(next_token(cmd));
                if (prim_type(mode) != PRIM_TYPE_BLOCK_MODE)
                    return rewind_token(cmd), 0;
                rec->action = ACTION_BLOCK_MODE;
                rec->m.block_mode.prim = prim;
                rec->m.block_mode.mode = mode;
                break;
            }
        default:
            return rewind_token(cmd), 0;
    }

    return !*cmd;
}

/*===----------------------------------------------------------------------===*/

/* The parameter-related functions below work as follows: they are first given
 * a (stack-allocated!) polymorphic parameter union, and then do either of two
 * things depending on whether there is anything special to add as parameter:
 *
 * - fill in the union depending on the primitive, and return that member
 * - nothing (i.e. default behaviour is desired), and return zero
 *
 * Then they can easily be used directly like this:
 *
 *     union xxx_PARAMS params;
 *     ...
 *     if (ordo_xxx(prim, xxx_params(prim, &params))) { ... }
*/

static void *get_block_params(prim_t prim, union BLOCK_PARAMS *params)
{
    return 0;
}

static void *get_stream_params(prim_t prim, union STREAM_PARAMS *params)
{
    switch (prim)
    {
        case STREAM_RC4:
            params->rc4.drop = 0;
            return &params->rc4;
    }

    return 0;
}

static void *get_hash_params(prim_t prim, union HASH_PARAMS *params)
{
    return 0;
}

static void *get_mode_params(prim_t prim, union BLOCK_MODE_PARAMS *params)
{
    switch (prim)
    {
        case BLOCK_MODE_ECB:
            params->ecb.padding = 0;
            return &params->ecb;
        case BLOCK_MODE_CBC:
            params->cbc.padding = 0;
            return &params->cbc;
    }

    return 0;
}

/*===----------------------------------------------------------------------===*/

/* We are going to need that much memory for the larger block tests anyway, so
 * we might as well reuse this scratch buffer for the key and iv buffers too.
*/

static unsigned char buffer[65536];
static unsigned char *key = buffer;
static unsigned char *iv  = buffer;

#define TIME_INTERVAL 10.0 /* Seconds per benchmark, higher = more precise. */

#define CHECK(cond) /* Error checking (by failing informatively on error). */\
    if (cond) exit((printf("\t* %s failed.\n\n", #cond), EXIT_FAILURE))

static double block_speed(prim_t prim, int inverse)
{
    struct BLOCK_LIMITS limits;
    union BLOCK_PARAMS params;
    struct BLOCK_STATE state;
    uint64_t iterations;
    double elapsed;

    CHECK(block_limits(prim, &limits));

    CHECK(block_init(&state, key, limits.key_max,
          prim, get_block_params(prim, &params)));

    if (inverse)
    {
        TIMER_START(elapsed, iterations, TIME_INTERVAL)
        block_inverse(&state, buffer);
        TIMER_STOP(elapsed)
    }
    else
    {
        TIMER_START(elapsed, iterations, TIME_INTERVAL)
        block_forward(&state, buffer);
        TIMER_STOP(elapsed)
    }

    block_final(&state);

    return (double)(limits.block_size * iterations) / (elapsed * 1024 * 1024);
}

static double stream_speed(prim_t prim, size_t block)
{
    union STREAM_PARAMS params;
    struct ENC_STREAM_CTX ctx;
    uint64_t iterations;
    double elapsed;

    size_t key_len = enc_stream_key_len(prim, (size_t)-1);

    CHECK(enc_stream_init(&ctx, key, key_len,
          prim, get_stream_params(prim, &params)));

    TIMER_START(elapsed, iterations, TIME_INTERVAL)
    enc_stream_update(&ctx, buffer, block);
    TIMER_STOP(elapsed)

    enc_stream_final(&ctx);

    return (double)(block * iterations) / (elapsed * 1024 * 1024);
}

static double hash_speed(prim_t prim, size_t block)
{
    union HASH_PARAMS params;
    struct DIGEST_CTX ctx;
    uint64_t iterations;
    double elapsed;

    CHECK(digest_init(&ctx, prim, get_hash_params(prim, &params)));

    TIMER_START(elapsed, iterations, TIME_INTERVAL)
    digest_update(&ctx, buffer, block);
    TIMER_STOP(elapsed)

    digest_final(&ctx, buffer);

    return (double)(block * iterations) / (elapsed * 1024 * 1024);
}

static double mode_speed(prim_t prim, prim_t mode, size_t block)
{
    union BLOCK_MODE_PARAMS mode_params;
    union BLOCK_PARAMS block_params;
    struct ENC_BLOCK_CTX ctx;
    uint64_t iterations;
    double elapsed;

    size_t iv_len = enc_block_iv_len(mode, prim, (size_t)-1);
    size_t key_len = enc_block_key_len(prim, (size_t)-1);
    size_t dummy; /* Don't care about output length. */

    CHECK(enc_block_init(&ctx, key, key_len, iv, iv_len, 1,
          prim, get_block_params(prim, &block_params),
          mode, get_mode_params(prim, &mode_params)));

    TIMER_START(elapsed, iterations, TIME_INTERVAL)
    enc_block_update(&ctx, buffer, block, buffer, &dummy);
    TIMER_STOP(elapsed)

    CHECK(enc_block_final(&ctx, buffer, &dummy));

    return (double)(block * iterations) / (elapsed * 1024 * 1024);
}

/*===----------------------------------------------------------------------===*/

static void bench_block(const struct BLOCK_RECORD *rec)
{
    printf("Benchmarking block cipher %s (raw):\n\n", prim_name(rec->prim));
    printf("\t*   (forward): %4.0f MiB/s\n", block_speed(rec->prim, 0));
    printf("\t*   (inverse): %4.0f MiB/s\n", block_speed(rec->prim, 1));
    printf("\nPerformance rated over %.2f seconds.\n", TIME_INTERVAL);
}

static void bench_stream(const struct STREAM_RECORD *rec)
{
    printf("Benchmarking stream cipher %s:\n\n", prim_name(rec->prim));
    printf("\t*    16 bytes: %4.0f MiB/s\n", stream_speed(rec->prim,    16));
    printf("\t*   256 bytes: %4.0f MiB/s\n", stream_speed(rec->prim,   256));
    printf("\t*  1024 bytes: %4.0f MiB/s\n", stream_speed(rec->prim,  1024));
    printf("\t*  4096 bytes: %4.0f MiB/s\n", stream_speed(rec->prim,  4096));
    printf("\t* 65536 bytes: %4.0f MiB/s\n", stream_speed(rec->prim, 65536));
    printf("\nPerformance rated over %.2f seconds.\n", TIME_INTERVAL);
}

static void bench_hash(const struct HASH_RECORD *rec)
{
    printf("Benchmarking hash function %s:\n\n", prim_name(rec->prim));
    printf("\t*    16 bytes: %4.0f MiB/s\n", hash_speed(rec->prim,    16));
    printf("\t*   256 bytes: %4.0f MiB/s\n", hash_speed(rec->prim,   256));
    printf("\t*  1024 bytes: %4.0f MiB/s\n", hash_speed(rec->prim,  1024));
    printf("\t*  4096 bytes: %4.0f MiB/s\n", hash_speed(rec->prim,  4096));
    printf("\t* 65536 bytes: %4.0f MiB/s\n", hash_speed(rec->prim, 65536));
    printf("\nPerformance rated over %.2f seconds.\n", TIME_INTERVAL);
}

static void bench_block_mode(const struct BLOCK_MODE_RECORD *rec)
{
    printf("Benchmarking block cipher %s in %s mode:\n\n",
           prim_name(rec->prim), prim_name(rec->mode));
    printf("\t*    16 bytes: %4.0f MiB/s\n",
           mode_speed(rec->prim, rec->mode, 16));
    printf("\t*   256 bytes: %4.0f MiB/s\n",
           mode_speed(rec->prim, rec->mode, 256));
    printf("\t*  1024 bytes: %4.0f MiB/s\n",
           mode_speed(rec->prim, rec->mode, 1024));
    printf("\t*  4096 bytes: %4.0f MiB/s\n",
           mode_speed(rec->prim, rec->mode, 4096));
    printf("\t* 65536 bytes: %4.0f MiB/s\n",
           mode_speed(rec->prim, rec->mode, 65536));
    printf("\nPerformance rated over %.2f seconds.\n", TIME_INTERVAL);
}

/*===----------------------------------------------------------------------===*/

static void print_prims(const char *description, enum PRIM_TYPE type)
{
    const prim_t *p;

    printf("\n%s\n\n\t", description);
    for (p = prims_by_type(type); *p; ++p)
    {
        printf("%s", prim_name(*p));
        if (*(p + 1)) printf(", ");
        else printf("\n");
    }
}

static void print_usage(const char *argv0)
{
    printf("Usage:\n\n\t%s [CMD ...]\n", argv0);

    print_prims("Available block ciphers:",
                PRIM_TYPE_BLOCK);
    print_prims("Available stream ciphers:",
                PRIM_TYPE_STREAM);
    print_prims("Available hash functions:",
                PRIM_TYPE_HASH);
    print_prims("Available block modes:",
                PRIM_TYPE_BLOCK_MODE);
}

int main(int argc, char *argv[])
{
    if (argc == 1)
    {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    while (*(++argv))
    {
        struct RECORD rec = {0};
        char *input_cmd = *argv;

        if (!parse_cmd(&input_cmd, &rec))
        {
            printf("Failed to parse '%s'.\n", input_cmd);
            return EXIT_FAILURE; /* A parsing failure. */
        }

        switch (rec.action)
        {
            case ACTION_BLOCK:
                bench_block(&rec.m.block);
                break;
            case ACTION_STREAM:
                bench_stream(&rec.m.stream);
                break;
            case ACTION_HASH:
                bench_hash(&rec.m.hash);
                break;
            case ACTION_BLOCK_MODE:
                bench_block_mode(&rec.m.block_mode);
                break;
        }

        if (*(argv + 1))
            printf("\n");
    }

    return EXIT_SUCCESS;
}
