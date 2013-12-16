#ifndef ORDO_API_H
#define ORDO_API_H

#include "ordo/internal/environment.h"

/******************************************************************************/

/*!
 * @internal
 * @file api.h
 * @brief Compile-time API definitions.
 *
 * This header defines the `ORDO_API`, `ORDO_INTERNAL`, and `ORDO_CALLCONV`
 * macros, which add the necessary export and calling convention symbols.
 * Almost every other header in the library will include this.
 *
 * Whether to export the function symbols or not is set by the existence of the
 * `ORDO_EXPORTS` preprocessor token, normally set by the CMake build system.
 *
 * This module is not to be used from outside the library, and is only
 * meaningful at compile-time.
*/

#ifdef __cplusplus
extern "C" {
#endif

/* Set the calling convention (identical for shared or static libraries).
 *
 * The current calling conventions are as follows:
 *
 * - Windows: use stdcall when possible.
 * - Linux/BSD: use the system default (usually cdecl).
*/

#if defined(COMPILER_MSVC)
    #define ORDO_CALLCONV __stdcall
#elif defined(COMPILER_GCC_LIKE)
    #if defined(PLATFORM_WINDOWS)
        #define ORDO_CALLCONV __attribute__((stdcall))
    #elif defined(PLATFORM_LINUX) || defined(PLATFORM_BSD)
        #define ORDO_CALLCONV
    #endif
#endif

#ifndef ORDO_CALLCONV
    #error No calling convention set.
#endif

/* Set the public/internal interface (export/import symbols, etc...). */

#if defined(ORDO_USING)
    #if defined(ORDO_USING_STATIC)
	    #define ORDO_API
	    #define ORDO_INTERNAL
	#elif defined(ORDO_USING_SHARED)
	    #if defined(COMPILER_MSVC)
	        #define ORDO_API __declspec(dllimport)
	        #define ORDO_INTERNAL
	    #elif defined(COMPILER_MINGW)
	        #define ORDO_API __declspec(dllimport)
	        #define ORDO_INTERNAL
	    #elif defined(COMPILER_GCC)
	        #define ORDO_API __attribute__((visibility("default")))
	        #define ORDO_INTERNAL __attribute__((visibility("hidden")))
	    #endif
    #endif
#elif defined(ORDO_BUILD)
    #if defined(ORDO_BUILD_STATIC)
	    #define ORDO_API
	    #define ORDO_INTERNAL
	#elif defined(ORDO_BUILD_SHARED)
	    #if defined(COMPILER_MSVC)
	        #define ORDO_API __declspec(dllexport)
	        #define ORDO_INTERNAL
	    #elif defined(COMPILER_MINGW)
	        #define ORDO_API __declspec(dllexport)
	        #define ORDO_INTERNAL
	    #elif defined(COMPILER_GCC)
	        #define ORDO_API __attribute__((visibility("default")))
	        #define ORDO_INTERNAL __attribute__((visibility("hidden")))
	    #endif
    #endif
#endif

#ifndef ORDO_API
    #error No public interface set.
#endif

#ifndef ORDO_INTERNAL
    #error No internal interface set.
#endif

#ifdef __cplusplus
}
#endif

#endif
