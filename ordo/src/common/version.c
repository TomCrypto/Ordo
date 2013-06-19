#include <common/version.h>

#include <common/environment.h>

/******************************************************************************/

const struct ORDO_BUILD_INFO ordoInfo = {
/* Library version. */
"2.0.0",
/* Devtag. */
"Experimental",
/* Build. */
#if ORDO_DEBUG
"Debug",
#else
"Release",
#endif
/* Platform. */
#if PLATFORM_WINDOWS
"Windows",
#elif PLATFORM_LINUX
"Linux",
#endif
/* The ABI. */
#if ABI_LINUX_64
"Linux x64",
#elif ABI_WINDOWS_64
"Windows x64",
#elif ABI_CDECL
"cdecl x86",
#endif
/* The word size. */
#if ENVIRONMENT_32
32,
#elif ENVIRONMENT_64
64,
#endif
/* AES-NI support. */
#if FEATURE_AES
1,
#else
0,
#endif
};

const struct ORDO_BUILD_INFO* ordo_build_info() { return &ordoInfo; }
