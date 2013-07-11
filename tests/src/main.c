#include <common/version.h> /* Contains library version/build info. */
#include <testenv.h> /* Contains the library's unit test framework. */

#define line "+------------------------------------------------------+------+"
#define MAX_LEN 53 /* Long enough buffer to store anything to be displayed. */
static char *info_start = "", *info_end = "";
static char *pass = "PASS", *fail = "FAIL";

void display_header(void)
{
    char header[MAX_LEN + 1];

    const char *endianness = (ordo_endianness() == 0) ? "little" : "big";

    snprintf(header, MAX_LEN, "Ordo v%d.%d.%d for %s (%d-bit, %s-endian)",
             ordo_version_major(), ordo_version_minor(), ordo_version_rev(),
             ordo_platform(), ordo_word_size(), endianness);

    printf("%s\n", line);
    printf("| %s%-*s%s | %sTest%s |\n",
           info_start, MAX_LEN - 1, header, info_end,
           info_start, info_end);
    printf("%s\n", line);
}

void display_test(int index, int *passed, FILE *extended)
{
    char output[MAX_LEN + 1];
    const char *result;

    snprintf(output, MAX_LEN, "Test #%d.", index + 1);

    result = test(index)(output, MAX_LEN, extended) ? pass : fail;
    if (result == pass) ++(*passed);

    printf("| %-*s | %s |\n", MAX_LEN - 1, output, result);
}

void display_total(int total, int passed)
{
    char header[MAX_LEN + 1];

    const char *result = (total == passed) ? pass : fail;

    snprintf(header, MAX_LEN, "Total: %d/%d tests passed.", passed, total);

    printf("%s\n", line);
    printf("| %s%-*s%s | %s%s%s |\n",
           info_start, MAX_LEN - 1, header, info_end,
           info_start, result, info_end);
    printf("%s\n", line);
}

int parse_args(int argc, char *argv[], int *color, FILE **extended)
{
    int t;

    if (argc > 3) return 1;
    if (argc == 1) return 0;

    for (t = 1; t < argc; ++t)
    {
        if (!strcmp(argv[t], "-color")) *color = 1;
        else if (!strcmp(argv[t], "-extended")) *extended = stderr;
        else return 1;
    }

    return 0;
}

void print_usage(int argc, char *argv[])
{
    printf("Usage:\n");
    printf("\t%s          \truns the test driver (plain mode).\n", argv[0]);
    printf("\t%s -color   \truns the test driver using colors.\n", argv[0]);
    printf("\t%s -extended\toutputs extended test information.\n", argv[0]);
}

int main(int argc, char *argv[])
{
    FILE *extended = 0;
    int color = 0;
    ordo_init();

    if (parse_args(argc, argv, &color, &extended))
    {
        print_usage(argc, argv);
        return EXIT_FAILURE;
    }

    if (extended) fprintf(extended, "~~~ Ordo Test Driver ~~~\n\n");

    if (color)
    {
        /* Use ANSI escape codes in an attempt to colorize the test results. If
         * the terminal used does not support it, this will produce garbage. */
        pass = "\x1b[1;32mPASS\x1b[0m";
        fail = "\x1b[1;31mFAIL\x1b[0m";
        info_start = "\x1b[1;35m";
        info_end = "\x1b[0m";
    }

    if (!register_all_tests())
    {
        int total = test_count(), passed = 0, t;
        if (extended) fprintf(extended, "Running %d tests.\n", total);

        display_header();

        for (t = 0; t < total; ++t) display_test(t, &passed, extended);

        display_total(total, passed);

        if (extended) fprintf(extended, "~~~ END LOG ~~~\n");
        return (total == passed) ? EXIT_SUCCESS : EXIT_FAILURE;
    }
    
    if (extended) fprintf(extended, "~~~ END LOG ~~~\n");
    return EXIT_FAILURE; /* This should never happen. */
}
