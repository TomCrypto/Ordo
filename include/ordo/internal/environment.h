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

/* Detect if we are building a shared library, static library, or just using
 * headers in a different project (this is very important, do not touch). */

#if defined(BUILDING_ORDO) || defined(BUILDING_ordo)
    #define ORDO_BUILD
    #if defined(ORDO_EXPORTS) || defined(ordo_EXPORTS)
        #define ORDO_BUILD_SHARED
    #else
        #define ORDO_BUILD_STATIC
    #endif
#else
    #define ORDO_USING
    #if defined(ORDO_STATIC_LIB) || defined(ordo_STATIC_LIB)
        #define ORDO_USING_STATIC
    #else
        #define ORDO_USING_SHARED
    #endif
#endif

/* Detect the platform we are going to be building on. If the platform is
 * invalid, or cannot be detected, or some other reason, fail. */

#if defined(_WIN32) || defined(_WIN64)
    #define PLATFORM_WINDOWS
#elif defined(__linux__)
    #define PLATFORM_LINUX
#elif defined(__NetBSD__)
    #define PLATFORM_NETBSD
#elif defined(__OpenBSD__)
    #define PLATFORM_OPENBSD
#elif defined(__FreeBSD__)
    #define PLATFORM_FREEBSD
#else
    #error Platform not supported.
#endif

/* Detect if the system is 32-bit or 64-bit. */

#if defined(__LP64__) || defined(_WIN64)
    #define ENVIRONMENT_64
#else
    #define ENVIRONMENT_32
#endif

/* Detect different types of processors. */

#if defined(__x86_64__) \
 || defined(__amd64__)  \
 || defined(_M_AMD64)   \
 || defined(_M_X64)
    #define CPU_X86_64
#elif defined(__i386__) \
   || defined(__i386)   \
   || defined(_M_IX86)  \
   || defined(_X86_)
    #define CPU_X86
#elif defined(__ARMEL__) /* ? */
    #define CPU_ARM
#elif defined(__powerpc__)
    #define CPU_PPC
#endif

/* Detect the compiler being used. */

#if defined(__MINGW32__)
    #define COMPILER_MINGW
#elif defined(__GNUC__)
    #define COMPILER_GCC
#elif defined(_MSC_VER)
    #define COMPILER_MSVC
#else
    #error Compiler not supported.
#endif

/* Define some useful compiler groups (e.g. for specific syntax). */

#if defined(COMPILER_MINGW) \
 || defined(COMPILER_GCC)
    #define COMPILER_GCC_LIKE
#endif

/* Provide commonly used stuff like alignment syntax. */

#if defined(COMPILER_MSVC)
    #define ORDO_ALIGN(x) __declspec(align(x))
#elif defined(COMPILER_GCC_LIKE)
    #define ORDO_ALIGN(x) __attribute__ ((aligned(x)))
#endif

#if defined(COMPILER_MSVC)
    #define ORDO_HOT_CODE // no hot code semantics
#elif defined(COMPILER_GCC_LIKE)
    #define ORDO_HOT_CODE __attribute__ ((hot))
#endif

/* These are feature flags used to enable various optimizations. Note these
 * can be overriden via your compiler's options, since they are set from
 * whatever features the compiler reports are available for use. */

/* AES-NI instructions (hardware-accelerated AES) */
#if defined(__AES__)
    #define FEATURE_AES
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
