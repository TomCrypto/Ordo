#ifndef ORDO_ENVIRONMENT_H
#define ORDO_ENVIRONMENT_H

/******************************************************************************/

/*!
 * @internal
 * @file environment.h
 * @brief Compile-time environment detection.
 *
 * This header will provide definitions for the environment details under
 * which Ordo is being built, trying to unify various compiler-specific
 * details under a single interface.
 *
 * This file may only contain preprocessor macros as it is included in
 * assembly files - it cannot contain declarations.
 *
 * This module is not to be used from outside the library, and is only
 * meaningful at compile-time.
*/

#ifdef __cplusplus
extern "C" {
#endif

/* Detect the platform we are going to be building on. If the platform is
 * invalid, or cannot be detected, or some other reason, fail. */

#if _WIN32 || _WIN64
    #define PLATFORM_WINDOWS
#elif __linux__
    #define PLATFORM_LINUX
#elif __NetBSD__
    #define PLATFORM_NETBSD
#elif __OpenBSD__
    #define PLATFORM_OPENBSD
#elif __FreeBSD__
    #define PLATFORM_FREEBSD
#else
    #error Platform not supported.
#endif

/* Detect if the system is 32-bit or 64-bit. */

#if __LP64__ || _WIN64
    #define ENVIRONMENT_64
#else
    #define ENVIRONMENT_32
#endif

/* Detect different types of processors. */

#if __x86_64__
    #define CPU_X86_64
#elif __i386__
    #define CPU_X86
#elif __ARMEL__ /* ? */
    #define CPU_ARM
#endif

/* These are feature flags used to enable various optimizations. Note these
 * can be overriden via your compiler's options, since they are set from
 * whatever features the compiler reports are available for use. */

/* AES-NI instructions (hardware-accelerated AES) */
#ifdef __AES__
    #define FEATURE_AES
#endif

#ifdef __cplusplus
}
#endif

/* The PLATFORM_BSD flag is defined for *BSD variants. */
#if defined(PLATFORM_NETBSD)  \
 || defined(PLATFORM_OPENBSD) \
 || defined(PLATFORM_FREEBSD)
    #define PLATFORM_BSD
#endif

/* The PLATFORM_POSIX flag is defined for all platforms which behave in
 * similar ways (e.g. follow the POSIX standard, have the same standard
 * libraries, use the same ABI) and are in general basically the same. */
#if defined(PLATFORM_LINUX) \
 || defined(PLATFORM_BSD)
    #define PLATFORM_POSIX
#endif

#endif
