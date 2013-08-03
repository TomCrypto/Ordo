#ifndef ORDO_MEM_PARAMS_H
#define ORDO_MEM_PARAMS_H

#include "ordo/internal/environment.h"

/******************************************************************************/

/*!
 * @internal
 * @file params.h
 * @brief Memory allocator parameters.
 *
 * Defines sensible pool parameters for a given platform and architecture.
 * Generally this depends only on the architecture, since it represents
 * how much memory the pool will use.
 *
 * Those are largely heuristics, and can be modified if needed.
 *
 * This module is not to be used from outside the library, and is only
 * meaningful at compile-time.
*/

#ifdef __cplusplus
extern "C" {
#endif

/* For all processors which aren't generally used in embedded hardware and are
 * usually equipped with dedicated memory storage hardware (i.e. RAM sticks),
 * assume general purpose usage. */
#if defined(CPU_X86) || defined(CPU_X86_64) \
 || defined(CPU_ARM) || defined(CPU_PPC)

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
