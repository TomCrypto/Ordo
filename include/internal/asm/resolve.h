#ifndef ORDO_ASM_RESOLVE_H
#define ORDO_ASM_RESOLVE_H

#include <internal/environment.h>

/******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file resolve.h
 * \brief Assembly code path resolution.
 *
 * This header is designed to help library code switch between different code
 * paths, e.g. x86_64 code versus standard C, and so on, using environment.h.
 *
 * The following template should be followed, for consistency. Take RC4 as an
 * example. It has two code paths: one for x86_64 processors, and once for
 * all other hardware. But that assembly code path is also divided between a
 * Linux and a Windows version, to account for ABI differences. So this
 * header should declare one and \b only one of the following preprocessor
 * tokens:
 *
 * - \c RC4_X86_64_LINUX: use the x86_64 code path for Linux.
 * - \c RC4_X86_64_WINDOWS: use the x86_64 code path for Windows.
 * - \c RC4_STANDARD: use the standard C code path.
 *
 * Also, if `ORDO_DEBUG` is defined (i.e. Ordo is being compiled in debug
 * mode), the standard C code path \b must unconditionally be selected.

 * The relevant code (rc4.c and rc4.S) can then include/exclude accordingly,
 * simplifying maintenance costs and improving overall readability.
 *
 * This header is meant for internal use only.
 * \internal
*/

/* RC4 */
#ifdef ORDO_DEBUG
    #define RC4_STANDARD
#else
    #if (PLATFORM_LINUX && __x86_64__)
        #define RC4_X86_64_LINUX
    #elif (PLATFORM_WINDOWS && __x86_64__)
        #define RC4_X86_64_WINDOWS
    #else
        #define RC4_STANDARD
    #endif
#endif

/* Threefish-256 */
#ifdef ORDO_DEBUG
    #define THREEFISH256_STANDARD
#else
    #if (PLATFORM_LINUX && __x86_64__)
        #define THREEFISH256_X86_64_LINUX
    #elif (PLATFORM_WINDOWS && __x86_64__)
        #define THREEFISH256_X86_64_WINDOWS
    #else
        #define THREEFISH256_STANDARD
    #endif
#endif

/* AES */
#ifdef ORDO_DEBUG
    #define AES_STANDARD
#else
    #if (PLATFORM_LINUX && __x86_64__ && FEATURE_AES)
        #define AES_X86_64_LINUX
    #elif (PLATFORM_WINDOWS && __x86_64__ && FEATURE_AES)
        #define AES_X86_64_WINDOWS
    #else
        #define AES_STANDARD
    #endif
#endif

#ifdef __cplusplus
}
#endif

#endif
