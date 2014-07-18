/*===-- version.c --------------------------------------*- SAMPLE -*- C -*-===*/
/**
*** @file
*** @brief Sample
***
*** This sample shows how to use the version API to get library version info.
**/
/*===----------------------------------------------------------------------===*/

#include <stdlib.h>
#include <stdio.h>

#include "ordo.h"

int main(void)
{
    const struct ORDO_VERSION *version = ordo_version();
    const char *const *features = version->features;

    printf("Running version `%s`.\n", version->build);
    while (*features) printf("  * %s\n", *features++);

    return EXIT_SUCCESS;
}
