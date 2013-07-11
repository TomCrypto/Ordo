#ifndef ORDO_MEM_PARAMS_H
#define ORDO_MEM_PARAMS_H

#include <internal/environment.h>

/******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * @file params.h
 * @brief Memory allocator parameters.
 * @internal
 *
 * Defines sensible pool parameters for a given platform and architecture.
 * Generally this depends only on the architecture, since it represents
 * how much memory the pool will use.
 *
 * This module is for internal use only and must not be used outside the
 * library.
*/

/* For all x86 and x86_64 processors, assume general-purpose usage. */
#if defined(__x86_64__) || defined(__i386__)

    #define POOL_SIZE 1024
    #define POOL_WORD 32

#endif

#if defined(POOL_SIZE) && defined(POOL_WORD)

    #define POOL_LEN (POOL_SIZE * POOL_WORD)

#else

    #error No memory pool parameters defined for this platform!

#endif

#ifdef __cplusplus
}
#endif

#endif
