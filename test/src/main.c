#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "testenv.h"

static int parse_args(int argc, char *argv[], struct DRIVER_OPTIONS *opt)
{
    opt->color = (argc == 2) && (!strcmp(argv[1], "--color"));
    return opt->color || (argc == 1); /* For print_usage(). */
}

static void print_usage(int argc, char *argv[])
{
    printf("Usage:\n");
    printf("\t%s         \truns the test driver (plain mode).\n", argv[0]);
    printf("\t%s --color \truns the test driver using colors.\n", argv[0]);
}

int main(int argc, char *argv[])
{
    struct DRIVER_OPTIONS opt;

    if (!parse_args(argc, argv, &opt))
    {
        print_usage(argc, argv);
        return EXIT_FAILURE;
    }
    
    return run_test_driver(opt) ? EXIT_SUCCESS : EXIT_FAILURE;
}
