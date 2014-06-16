/* Sample for Ordo - version.c
 * ===============
 *
 * Shows how to use the version API to get library version information.
*/

#include <stdlib.h>
#include <stdio.h>

#include "ordo.h"

int main(void)
{
    const struct ORDO_VERSION *version = ordo_version();
    const char *const *features = version->features;

    printf("Running %s (%d)\n", version->build, version->id);
    while (*features) printf("  * %s\n", *features++);

    return EXIT_SUCCESS;
}
