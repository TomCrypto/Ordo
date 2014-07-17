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

static void timer_init(double seconds);
static int timer_has_elapsed(void);
static double timer_now(void);
static void timer_free(void);

#if defined(_WIN32) /* On Windows, use system functions. */

/* TODO: untested! */

#include <windows.h>
#include <signal.h>

static HANDLE timer_id;

static volatile sig_atomic_t timer_elapsed;

void timer_handler(void *unused1, DWORD unused2, DWORD unused3)
{
    timer_elapsed = 1;
}

void timer_init(double seconds)
{
    LARGE_INTEGER due_time; /* 100 nanosecond steps. */
    due_time.QuadPart = (LONGLONG)(seconds * 10000000);

    if (!(timer_id = CreateWaitableTimer(0, 1, 0)))
    {
        printf("CreateWaitableTimer failed (%u).\n", GetLastError());
        exit(EXIT_FAILURE);
    }

    if (!SetWaitableTimer(timer_id, &due_time, 0, timer_handler, 0, 0))
    {
        printf("SetWaitableTimer failed (%u).\n", GetLastError());
        exit(EXIT_FAILURE);
    }
}


int timer_has_elapsed(void)
{
    return timer_elapsed;
}

double timer_now(void)
{
    static LARGE_INTEGER freq = {0};
    LARGE_INTEGER counter;

    if (!freq.QuadPart)
        QueryPerformanceFrequency(&freq);

    QueryPerformanceCounter(&counter);
    return (double)counter.QuadPart / freq.QuadPart;
}

void timer_free(void)
{
    CloseHandle(timer_id);
}

#else /* Assume we are on a POSIX 1993 compliant system. */

#define _POSIX_C_SOURCE 1993109L

#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

static timer_t timer_id;

static volatile sig_atomic_t timer_elapsed;

static void timer_handler(int unused)
{
    timer_elapsed = 1;
}

void timer_init(double seconds)
{
    struct sigaction sig;
    struct itimerspec tm;

    double frac = seconds - (long)seconds;

    tm.it_interval.tv_nsec = frac / 1000000000;
    tm.it_interval.tv_sec = (time_t)seconds;
    tm.it_value = tm.it_interval;
    timer_elapsed = 0;

    sig.sa_handler = timer_handler;
    sigemptyset(&sig.sa_mask);
    sig.sa_flags = 0;

    if (timer_create(CLOCK_MONOTONIC, 0, &timer_id))
    {
        perror("timer_create");
        exit(EXIT_FAILURE);
    }

    if (timer_settime(timer_id, 0, &tm, 0))
    {
        perror("timer_settime");
        exit(EXIT_FAILURE);
    }

    if (sigaction(SIGALRM, &sig, 0))
    {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }
}

int timer_has_elapsed(void)
{
    return timer_elapsed;
}

double timer_now(void)
{
    struct timespec tv;
    clock_gettime(CLOCK_MONOTONIC, &tv);
    return tv.tv_sec + tv.tv_nsec / 1000000000.0;
}

void timer_free(void)
{
    timer_delete(timer_id);
}

#undef _POSIX_C_SOURCE

#endif

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

static union BLOCK_PARAMS *get_block_params(
    prim_t prim, union BLOCK_PARAMS *params)
{
    return 0;
}

static union STREAM_PARAMS *get_stream_params(
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

static union HASH_PARAMS *get_hash_params(
    prim_t prim, union HASH_PARAMS *params)
{
    return 0;
}

static union BLOCK_MODE_PARAMS *get_mode_params(
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

/* We are going to need that much memory for the larger block tests anyway, so
 * we might as well use this scratch buffer for the key/iv buffers as well. */
static char buffer[65536];

#define TIME_INTERVAL 15.0 /* seconds */

#define TIME_BLOCK(counter, duration, elapsed, statement)\
    counter = 0;\
    timer_init(duration);\
    elapsed = timer_now();\
    while (++counter && !timer_has_elapsed())\
        do { statement } while (0);\
    elapsed = timer_now() - elapsed;\
    timer_free();

#define COMPUTE_SPEED(throughput, elapsed)\
    ((throughput) / ((elapsed) * 1024 * 1024))

static double hash_speed(prim_t prim, size_t block)
{
    union HASH_PARAMS params;
    struct DIGEST_CTX ctx;
    uint64_t iterations;
    double elapsed;

    digest_init(&ctx, prim, get_hash_params(prim, &params));

    TIME_BLOCK(iterations, TIME_INTERVAL, elapsed, {
        digest_update(&ctx, buffer, block);
    });

    digest_final(&ctx, buffer);

    return COMPUTE_SPEED(block * iterations, elapsed);
}

static double stream_speed(prim_t prim, size_t block)
{
    union STREAM_PARAMS params;
    struct ENC_STREAM_CTX ctx;
    uint64_t iterations;
    double elapsed;

    size_t key_len = enc_stream_key_len(prim, (size_t)-1);

    enc_stream_init(&ctx, buffer, key_len,
                    prim, get_stream_params(prim, &params));

    TIME_BLOCK(iterations, TIME_INTERVAL, elapsed, {
        enc_stream_update(&ctx, buffer, block);
    });

    enc_stream_final(&ctx);

    return COMPUTE_SPEED(block * iterations, elapsed);
}

static double block_speed(prim_t prim, prim_t mode, size_t block)
{
    union BLOCK_MODE_PARAMS mode_params;
    union BLOCK_PARAMS block_params;
    struct ENC_BLOCK_CTX ctx;
    uint64_t iterations;
    double elapsed;

    size_t iv_len = block_mode_query(mode, prim, IV_LEN_Q, (size_t)-1);
    size_t key_len = block_query(prim, KEY_LEN_Q, (size_t)-1);
    size_t dummy; /* We don't care about the output length. */

    enc_block_init(&ctx, buffer, key_len, buffer, iv_len, 1,
                   prim, get_block_params(prim, &block_params),
                   mode, get_mode_params(prim, &mode_params));

    TIME_BLOCK(iterations, TIME_INTERVAL, elapsed, {
        enc_block_update(&ctx, buffer, block, buffer, &dummy);
    });

    enc_block_final(&ctx, buffer, &dummy);

    return COMPUTE_SPEED(block * iterations, elapsed);
}

/*===----------------------------------------------------------------------===*/

static int bench_hash(prim_t prim, int argc, char * const argv[])
{
    if (argc > 2)
        return printf("Unrecognized argument '%s'.\n", argv[2]), EXIT_FAILURE;

    printf("Benchmarking hash function %s:\n\n", argv[1]);
    printf("\t*    16 bytes: %4.0f MiB/s\n", hash_speed(prim,    16));
    printf("\t*   256 bytes: %4.0f MiB/s\n", hash_speed(prim,   256));
    printf("\t*  1024 bytes: %4.0f MiB/s\n", hash_speed(prim,  1024));
    printf("\t*  4096 bytes: %4.0f MiB/s\n", hash_speed(prim,  4096));
    printf("\t* 65536 bytes: %4.0f MiB/s\n", hash_speed(prim, 65536));
    printf("\nPerformance rated over %.2f seconds.\n", TIME_INTERVAL);

    return EXIT_SUCCESS;
}

static int bench_stream(prim_t prim, int argc, char * const argv[])
{
    if (argc > 2)
        return printf("Unrecognized argument '%s'.\n", argv[2]), EXIT_FAILURE;

    printf("Benchmarking stream cipher %s:\n\n", argv[1]);
    printf("\t*    16 bytes: %4.0f MiB/s\n", stream_speed(prim,    16));
    printf("\t*   256 bytes: %4.0f MiB/s\n", stream_speed(prim,   256));
    printf("\t*  1024 bytes: %4.0f MiB/s\n", stream_speed(prim,  1024));
    printf("\t*  4096 bytes: %4.0f MiB/s\n", stream_speed(prim,  4096));
    printf("\t* 65536 bytes: %4.0f MiB/s\n", stream_speed(prim, 65536));
    printf("\nPerformance rated over %.2f seconds.\n", TIME_INTERVAL);

    return EXIT_SUCCESS;
}

static int bench_block(prim_t prim, int argc, char * const argv[])
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
    printf("\t*    16 bytes: %4.0f MiB/s\n", block_speed(prim, mode,    16));
    printf("\t*   256 bytes: %4.0f MiB/s\n", block_speed(prim, mode,   256));
    printf("\t*  1024 bytes: %4.0f MiB/s\n", block_speed(prim, mode,  1024));
    printf("\t*  4096 bytes: %4.0f MiB/s\n", block_speed(prim, mode,  4096));
    printf("\t* 65536 bytes: %4.0f MiB/s\n", block_speed(prim, mode, 65536));
    printf("\nPerformance rated over %.2f seconds.\n", TIME_INTERVAL);

    return EXIT_SUCCESS;
}

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
