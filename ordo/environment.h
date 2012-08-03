#ifndef environment_h
#define environment_h

/**
 * @file environment.h
 * Precompilation environment decision unit. This will decide whether to use the 32-bit or 64-bit version of Ordo
 * and set the appropriate flags for conditional compilation throughout the library. Please make sure you include
 * this file when linking assembler files as they will always be preprocessed prior to this header.
 *
 * \todo Implement more platforms (and make sure they all work)
 */

/* Decides whether the build target is a 32-bit or 64-bit platform. */
#if _WIN32 || _WIN64
#if _WIN64
#define ENVIRONMENT64
#else
#define ENVIRONMENT32
#endif
#endif

#if __GNUC__
#if __x86_64__ || __ppc64__
#define ENVIRONMENT64
#else
#define ENVIRONMENT32
#endif
#endif

#ifndef ENVIRONMENT64
#ifndef ENVIRONMENT32
#error "Unknown platform."
#endif
#endif

#endif
