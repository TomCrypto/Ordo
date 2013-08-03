#include "ordo/common/version.h"

#include "ordo/internal/environment.h"

/******************************************************************************/

#define VERSION_MAJOR 2
#define VERSION_MINOR 3
#define VERSION_REV   1

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

#if defined(PLATFORM_WINDOWS)
static const char *platform = "Windows";
#elif defined(PLATFORM_LINUX)
static const char *platform = "Linux";
#elif defined(PLATFORM_OPENBSD)
static const char *platform = "OpenBSD";
#elif defined(PLATFORM_FREEBSD)
static const char *platform = "FreeBSD";
#elif defined(PLATFORM_NETBSD)
static const char *platform = "NetBSD";
#endif

const char *ordo_platform()
{
    return platform;
}

int ordo_word_size()
{
    #if defined(ENVIRONMENT_32)
    return 32;
    #elif defined(ENVIRONMENT_64)
    return 64;
    #endif
}
