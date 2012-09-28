#include <common/version.h>

const ORDO_BUILD_INFO ordoInfo = {
/* Library version. */
"1.5.0",
/* Devtag. */
"Stable/Hashes",
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

const ORDO_BUILD_INFO* ordoBuildInfo() { return &ordoInfo; }
