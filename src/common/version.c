#include <common/version.h>

/******************************************************************************/

#define VERSION_MAJOR 2
#define VERSION_MINOR 1
#define VERSION_REV   0

int ordo_version_major()
{
    return VERSION_MAJOR;
}

int ordo_version_minor()
{
    return VERSION_MINOR;
}

int ordo_version_rev()
{
    return VERSION_REV;
}
