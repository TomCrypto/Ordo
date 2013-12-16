#include "ordo/common/version.h"

#include "ordo/internal/environment.h"

/******************************************************************************/

#define VERSION_MAJOR 2
#define VERSION_MINOR 4
#define VERSION_REV   0

int ORDO_CALLCONV
ordo_version_major(void)
{
    return VERSION_MAJOR;
}

int ORDO_CALLCONV
ordo_version_minor(void)
{
    return VERSION_MINOR;
}

int ORDO_CALLCONV
ordo_version_rev(void)
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

const char * ORDO_CALLCONV
ordo_platform(void)
{
    return platform;
}

int ORDO_CALLCONV
ordo_word_size(void)
{
    #if defined(ENVIRONMENT_32)
    return 32;
    #elif defined(ENVIRONMENT_64)
    return 64;
    #endif
}
