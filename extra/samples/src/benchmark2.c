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
***         ./benchmark [CMD ...]
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

void CALLBACK timer_handler(void *unused1, DWORD unused2, DWORD unused3)
{
    timer_elapsed = 1;
}

void timer_init(double seconds)
{
    LARGE_INTEGER due_time; /* 100-nanosecond steps format. */
    due_time.QuadPart = (-1) * (LONGLONG)(seconds * 10000000);
    timer_elapsed = 0;

    if (!(timer_id = CreateWaitableTimer(0, TRUE, 0)))
    {
        printf("CreateWaitableTimer failed (%u).\n", GetLastError());
        exit(EXIT_FAILURE);
    }

    if (!SetWaitableTimer(timer_id, &due_time, 0, timer_handler, 0, FALSE))
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
static struct sigaction timer_old;
static volatile sig_atomic_t timer_elapsed;

static void timer_handler(int unused)
{
    timer_elapsed = 1;
}

void timer_init(double seconds)
{
    struct sigevent evp = {0};
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

    evp.sigev_value.sival_ptr = &timer_id;
    evp.sigev_notify = SIGEV_SIGNAL;
    evp.sigev_signo = SIGALRM;

    if (timer_create(CLOCK_MONOTONIC, &evp, &timer_id))
    {
        perror("timer_create");
        exit(EXIT_FAILURE);
    }

    if (timer_settime(timer_id, 0, &tm, 0))
    {
        perror("timer_settime");
        exit(EXIT_FAILURE);
    }

    if (sigaction(SIGALRM, &sig, &timer_old))
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
    sigaction(SIGALRM, &timer_old, 0);
    timer_delete(timer_id);
}

#undef _POSIX_C_SOURCE

#endif

/*===----------------------------------------------------------------------===*/

#include <stdlib.h>
#include <string.h>
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

#define TIME_INTERVAL 10.0 /* seconds */

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

static double block_speed(prim_t prim)
{
    union BLOCK_PARAMS params;
    struct BLOCK_STATE state;
    uint64_t iterations;
    double elapsed;

    size_t block_size = block_query(prim, BLOCK_SIZE_Q, (size_t)-1);
    size_t key_len = block_query(prim, KEY_LEN_Q, (size_t)-1);

    block_init(&state, buffer, key_len,
               prim, get_block_params(prim, &params));

    TIME_BLOCK(iterations, TIME_INTERVAL, elapsed, {
        block_forward(&state, buffer);
    });

    block_final(&state);

    return COMPUTE_SPEED(block_size * iterations, elapsed);
}

static double mode_speed(prim_t prim, prim_t mode, size_t block)
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

static void bench_hash(prim_t prim)
{
    printf("Benchmarking hash function %s:\n\n", prim_name(prim));
    printf("\t*    16 bytes: %4.0f MiB/s\n", hash_speed(prim,    16));
    printf("\t*   256 bytes: %4.0f MiB/s\n", hash_speed(prim,   256));
    printf("\t*  1024 bytes: %4.0f MiB/s\n", hash_speed(prim,  1024));
    printf("\t*  4096 bytes: %4.0f MiB/s\n", hash_speed(prim,  4096));
    printf("\t* 65536 bytes: %4.0f MiB/s\n", hash_speed(prim, 65536));
    printf("\nPerformance rated over %.2f seconds.\n", TIME_INTERVAL);
}

static void bench_stream(prim_t prim)
{
    printf("Benchmarking stream cipher %s:\n\n", prim_name(prim));
    printf("\t*    16 bytes: %4.0f MiB/s\n", stream_speed(prim,    16));
    printf("\t*   256 bytes: %4.0f MiB/s\n", stream_speed(prim,   256));
    printf("\t*  1024 bytes: %4.0f MiB/s\n", stream_speed(prim,  1024));
    printf("\t*  4096 bytes: %4.0f MiB/s\n", stream_speed(prim,  4096));
    printf("\t* 65536 bytes: %4.0f MiB/s\n", stream_speed(prim, 65536));
    printf("\nPerformance rated over %.2f seconds.\n", TIME_INTERVAL);
}

static void bench_block(prim_t prim)
{
    printf("Benchmarking block cipher %s (raw):\n\n", prim_name(prim));
    printf("\t*       (raw): %4.0f MiB/s\n", block_speed(prim));
    printf("\nPerformance rated over %.2f seconds.\n", TIME_INTERVAL);
}

static void bench_block_mode(prim_t prim, prim_t mode)
{
    const char *pr_name = prim_name(prim);
    const char *md_name = prim_name(mode);

    printf("Benchmarking block cipher %s in %s mode:\n\n", pr_name, md_name);
    printf("\t*    16 bytes: %4.0f MiB/s\n", mode_speed(prim, mode,    16));
    printf("\t*   256 bytes: %4.0f MiB/s\n", mode_speed(prim, mode,   256));
    printf("\t*  1024 bytes: %4.0f MiB/s\n", mode_speed(prim, mode,  1024));
    printf("\t*  4096 bytes: %4.0f MiB/s\n", mode_speed(prim, mode,  4096));
    printf("\t* 65536 bytes: %4.0f MiB/s\n", mode_speed(prim, mode, 65536));
    printf("\nPerformance rated over %.2f seconds.\n", TIME_INTERVAL);
}

/*===----------------------------------------------------------------------===*/

enum ACTION
{
    ACTION_HASH,
    ACTION_STREAM,
    ACTION_BLOCK_RAW,
    ACTION_BLOCK_MODE
};

struct RECORD
{
    enum ACTION action;
    prim_t prim, prim2;
};

static char *tokenize(char **str)
{
    char *start = *str;

    if (*str)
    {
        char *delim = strstr(*str, "/");
        *str = delim ? delim + 1 : 0;
        if (delim) *delim = '\0';
    }

    return start;
}

static int parse_cmd(char **cmd, struct RECORD *rec)
{
    switch (prim_type(rec->prim = prim_from_name(tokenize(cmd))))
    {
        case PRIM_TYPE_HASH:
            rec->action = ACTION_HASH;
            break;
        case PRIM_TYPE_STREAM:
            rec->action = ACTION_STREAM;
            break;
        case PRIM_TYPE_BLOCK:
            if (!*cmd)
            {
                rec->action = ACTION_BLOCK_RAW;
                break; /* Raw mode block cipher */
            }
            else
            {
                if (prim_type(rec->prim2 = prim_from_name(tokenize(cmd)))
                    != PRIM_TYPE_BLOCK_MODE) return 0;
                rec->action = ACTION_BLOCK_MODE;
                break; /* Block cipher + mode */
            }
        default:
            return 0;
    }

    return !*cmd;
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
        struct RECORD rec;
        char *cmd = *argv;

        if (!parse_cmd(&cmd, &rec))
        {
            printf("Failed to parse '%s'.\n", cmd);
            return EXIT_FAILURE; /* Parse error. */
        }

        switch (rec.action)
        {
            case ACTION_HASH:
                bench_hash(rec.prim);
                break;
            case ACTION_STREAM:
                bench_stream(rec.prim);
                break;
            case ACTION_BLOCK_RAW:
                bench_block(rec.prim);
                break;
            case ACTION_BLOCK_MODE:
                bench_block_mode(rec.prim, rec.prim2);
                break;
        }

        if (*(argv + 1))
            printf("\n");
    }

    return EXIT_SUCCESS;
}
