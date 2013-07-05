#ifndef ORDO_ENVIRONMENT_H
#define ORDO_ENVIRONMENT_H

/******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * @file environment.h
 * @brief Compile-time environment detection.
 * @internal
 *
 * This header will provide definitions for the environment details under
 * which Ordo is being built, trying to unify various compiler-specific
 * details under a single interface.
 *
 * This file may only contain preprocessor macros as it is included in
 * assembly files - it cannot contain declarations.
*/

/* Detect the platform we are going to be building on. If the platform is
 * invalid, or cannot be detected, or some other reason, fail. */

#if _WIN32 || _WIN64
    #define PLATFORM_WINDOWS 1
#elif __linux__
    #define PLATFORM_LINUX 1
#elif __NetBSD__
    #define PLATFORM_NETBSD 1
#elif __OpenBSD__
    #define PLATFORM_OPENBSD 1
#elif __FreeBSD__
    #define PLATFORM_FREEBSD 1
#else
    #error "Platform not supported."
#endif

/* Detect if the system is 32-bit or 64-bit. */

#if __LP64__
    #define ENVIRONMENT_64 1
#else
    #define ENVIRONMENT_32 1
#endif

/* These are feature flags used to enable various optimizations. Note these
 * can be overriden via your compiler's options, since they are set from
 * whatever features the compiler reports are available for use. */

/* AES-NI instructions (hardware-accelerated AES) */
#ifdef __AES__
    #define FEATURE_AES 1
#else
    #define FEATURE_AES 0
#endif

#ifdef __cplusplus
}
#endif

#endif
