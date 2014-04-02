/* Color configuration, except pass/fail/etc, feel free to edit. */

#define groupname(str) yellow(str)
#define version(str) cyan(str)
#define test(str) cyan(str)

/* ---- */

#include "testenv.h"
#include "tests.h"

#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <time.h>

#include "ordo/common/version.h"

static int enable_colors;
static char *pass_str;
static char *fail_str;
static char *warn_str;
static char *info_str;

#define CACHE_SIZE 8

static char *cache[CACHE_SIZE];
static size_t count = 0;

static void cleanup(void)
{
    size_t t;

    for (t = 0; t < CACHE_SIZE; ++t)
        free(cache[t]);
}

const char *colorize(const char *str, enum LOG_COLOR color, int bold)
{
    if (enable_colors)
    {
        if (count == CACHE_SIZE) count = 0;
        if (cache[count]) free(cache[count]);
        cache[count] = malloc(strlen(str) + 12);
        sprintf(cache[count], "\x1b[%d;3%dm%s\x1b[0m",
                              bold == 1, color, str);
        return cache[count++];
    }

    return str;
}

static void init_log(struct DRIVER_OPTIONS opt)
{
    if ((enable_colors = opt.color))
    {
        pass_str = "\x1b[1m[\x1b[0m\x1b[1;32mpass\x1b[0m\x1b[1m]\x1b[0m";
        fail_str = "\x1b[1m[\x1b[0m\x1b[1;31mfail\x1b[0m\x1b[1m]\x1b[0m";
        warn_str = "\x1b[1m[\x1b[0m\x1b[1;33mwarn\x1b[0m\x1b[1m]\x1b[0m";
        info_str = "\x1b[1m[\x1b[0m\x1b[1;36minfo\x1b[0m\x1b[1m]\x1b[0m";
    }
    else
    {
        pass_str = "[pass]";
        fail_str = "[fail]";
        warn_str = "[warn]";
        info_str = "[info]";
    }

    atexit(cleanup);
}

void lprintf(enum LOG_STATUS status, const char *fmt, ...)
{
    switch (status)
    {
        case PASS: printf("%s ", pass_str); break;
        case FAIL: printf("%s ", fail_str); break;
        case WARN: printf("%s ", warn_str); break;
        case INFO: printf("%s ", info_str); break;
    }

    {
        va_list args;
        va_start(args, fmt);
        vprintf(fmt, args);
        va_end(args);
        printf("\n");
    }
}

static int run_test_group(struct TEST_GROUP group)
{
    size_t passed = 0, t;

    for (t = 0; t < group.test_count; ++t)
    {
        int retval = group.list[t].run() ? 1 : 0; passed += retval;
        lprintf(retval ? PASS : FAIL, "%s.", test(group.list[t].name));
    }

    return passed == group.test_count;
}

int run_test_driver(struct DRIVER_OPTIONS opt)
{
    init_log(opt);
    srand((unsigned)time(0));
    printf("Ordo Test Driver\n");
    printf("================\n");
    printf("\n"); /* Let's go! */
    
    {
        const char *f = ordo_version()->feature_list; /* Extra information. */
        lprintf(INFO, "Library version: %s.", version(ordo_version()->build));
        if (strlen(f) != 0) lprintf(INFO, "Target features: %s.", version(f));
    }
    
    {
        size_t passed = 0, t;

        for (t = 0; t < GROUP_COUNT; ++t)
        {
            int retval = run_test_group(tests[t]) ? 1 : 0; passed += retval;
            lprintf(retval ? PASS : FAIL, "%s.", groupname(tests[t].group));
        }

        printf("\n================\n"); /* Any failure gets reported. */
        printf("Outcome => %s!\n", passed == GROUP_COUNT ? bgreen("PASS")
                                                         : bred  ("FAIL"));
        return passed == GROUP_COUNT;
    }
}
