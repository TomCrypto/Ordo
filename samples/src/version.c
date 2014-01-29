// Shows how to use the version API.

#include <stdlib.h>
#include <stdio.h>

#include "ordo.h"

int main(void)
{
    const struct ORDO_VERSION *version = ordo_version();
    size_t t;
    
    printf("Running %s.\n", version->build);
    printf("  ID          : %d\n", version->id);
    printf("  version     : %s\n", version->version);
    printf("  system      : %s\n", version->system);
    printf("  architecture: %s\n", version->arch);
    printf("  features    : %s\n", version->feature_list);
    printf("  or as array :\n");
    
    for (t = 0; version->features[t]; ++t)
        printf("  - %s\n", version->features[t]);
        
    return EXIT_SUCCESS;
}
