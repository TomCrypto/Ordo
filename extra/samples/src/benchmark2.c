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
***     ./benchmark Threefish-256/inverse
**/
/*===----------------------------------------------------------------------===*/

static void timer_init(double seconds);
static int timer_has_elapsed(void);
static double timer_now(void);
static void timer_free(void);

#if defined(_WIN32) /* On Windows, use system functions. */

#include <windows.h>
#include <signal.h>
#include <stdio.h>

static HANDLE timer_id;
static volatile sig_atomic_t timer_elapsed;

void CALLBACK timer_handler(void *aux, BOOLEAN unused)
{
    timer_elapsed = 1;
}

void timer_init(double seconds)
{
    timer_elapsed = 0;

    if (!CreateTimerQueueTimer(&timer_id, 0, timer_handler, 0,
                               (DWORD)(seconds * 1000), 0,
                               WT_EXECUTEONLYONCE))
    {
        printf("CreateTimerQueueTimer failed.\n");
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
    DeleteTimerQueueTimer(0, timer_id, 0);
}

#elif defined(__OpenBSD__)

#include <time.h>

static double timer_delta, timer_start;

void timer_init(double seconds)
{
    timer_start = timer_now();
    timer_delta = seconds;
}

int timer_has_elapsed(void)
{
    return (timer_now() - timer_start) >= timer_delta;
}

double timer_now(void)
{
    struct timespec tv;
    clock_gettime(CLOCK_MONOTONIC, &tv);
    return tv.tv_sec + tv.tv_nsec / 1000000000.0;
}

void timer_free(void)
{
    return;
}

#elif defined(__APPLE__)

#include <sys/time.h>

static double timer_delta, timer_start;

void timer_init(double seconds)
{
    timer_start = timer_now();
    timer_delta = seconds;
}

int timer_has_elapsed(void)
{
    return (timer_now() - timer_start) >= timer_delta;
}

double timer_now(void)
{
    struct timeval tv;

    gettimeofday(&tv, 0);
    return tv.tv_sec + tv.tv_usec / 1000000.0;
}

void timer_free(void)
{
    return;
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

    tm.it_interval.tv_nsec = seconds - (long)seconds / 1000000000;
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

struct BLOCK_RECORD
{
    prim_t prim;
    int inverse;
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
    int direction;
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
                rec->m.block.inverse = 0;
                break;
            }
            else
            {
                char *next = next_token(cmd);
                if (!strcmp(next, "inverse"))
                {
                    rec->action = ACTION_BLOCK;
                    rec->m.block.prim = prim;
                    rec->m.block.inverse = 1;
                    break;
                }
                else
                {
                    prim_t mode = prim_from_name(next);
                    if (prim_type(mode) != PRIM_TYPE_BLOCK_MODE)
                        return rewind_token(cmd), 0;
                    rec->action = ACTION_BLOCK_MODE;
                    rec->m.block_mode.prim = prim;
                    rec->m.block_mode.mode = mode;
                    break;
                }
            }
        default:
            return 0;
    }

    return !*cmd;
}

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
    ((double)(throughput) / ((double)(elapsed) * 1024 * 1024))

#define FAIL(msg){\
    printf("\t* %s\n\n", msg);\
    exit(EXIT_FAILURE);\
    }

static double block_speed(prim_t prim, int inverse)
{
    union BLOCK_PARAMS params;
    struct BLOCK_STATE state;
    uint64_t iterations;
    double elapsed;

    size_t block_size = block_query(prim, BLOCK_SIZE_Q, (size_t)-1);
    size_t key_len = block_query(prim, KEY_LEN_Q, (size_t)-1);

    if (block_init(&state, buffer, key_len,
                   prim, get_block_params(prim, &params)))
        FAIL("block_init failed.");

    if (inverse)
    {
        TIME_BLOCK(iterations, TIME_INTERVAL, elapsed, {
            block_inverse(&state, buffer);
        });
    }
    else
    {
        TIME_BLOCK(iterations, TIME_INTERVAL, elapsed, {
            block_forward(&state, buffer);
        });
    }

    block_final(&state);

    return COMPUTE_SPEED(block_size * iterations, elapsed);
}

static double stream_speed(prim_t prim, size_t block)
{
    union STREAM_PARAMS params;
    struct ENC_STREAM_CTX ctx;
    uint64_t iterations;
    double elapsed;

    size_t key_len = enc_stream_key_len(prim, (size_t)-1);

    if (enc_stream_init(&ctx, buffer, key_len,
                        prim, get_stream_params(prim, &params)))
        FAIL("enc_stream_init failed.");

    TIME_BLOCK(iterations, TIME_INTERVAL, elapsed, {
        enc_stream_update(&ctx, buffer, block);
    });

    enc_stream_final(&ctx);

    return COMPUTE_SPEED(block * iterations, elapsed);
}

static double hash_speed(prim_t prim, size_t block)
{
    union HASH_PARAMS params;
    struct DIGEST_CTX ctx;
    uint64_t iterations;
    double elapsed;

    if (digest_init(&ctx, prim, get_hash_params(prim, &params)))
        FAIL("digest_init failed.");

    TIME_BLOCK(iterations, TIME_INTERVAL, elapsed, {
        digest_update(&ctx, buffer, block);
    });

    digest_final(&ctx, buffer);

    return COMPUTE_SPEED(block * iterations, elapsed);
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

    if (enc_block_init(&ctx, buffer, key_len, buffer, iv_len, 1,
                       prim, get_block_params(prim, &block_params),
                       mode, get_mode_params(prim, &mode_params)))
        FAIL("enc_block_init failed.");

    TIME_BLOCK(iterations, TIME_INTERVAL, elapsed, {
        enc_block_update(&ctx, buffer, block, buffer, &dummy);
    });

    if (enc_block_final(&ctx, buffer, &dummy))
        FAIL("enc_block_final failed.");

    return COMPUTE_SPEED(block * iterations, elapsed);
}

/*===----------------------------------------------------------------------===*/

static void bench_block(const struct BLOCK_RECORD *rec)
{
    printf("Benchmarking block cipher %s (raw, %s):\n\n",
           prim_name(rec->prim), rec->inverse ? "inverse" : "forward");
    printf("\t*       (raw): %4.0f MiB/s\n",
           block_speed(rec->prim, rec->inverse));
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
        struct RECORD rec;
        char *cmd = *argv;

        if (!parse_cmd(&cmd, &rec))
        {
            printf("Failed to parse '%s'.\n", cmd);
            return EXIT_FAILURE; /* Parse error. */
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
