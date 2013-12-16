#ifndef ORDO_SKEIN256_H
#define ORDO_SKEIN256_H

#include "ordo/internal/api.h"

#include "ordo/primitives/hash_functions/hash_params.h"

/******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * @file skein256.h
 * @brief Skein-256 hash function.
 *
 * This is the Skein-256 hash function, which produces a 256-bit digest by
 * default (but has parameters to output a longer digest) and has a 256-bit
 * internal state. This implementation supports messages up to a length of
 * 2^64 - 1 bytes instead of the 2^96 - 1 available, but we trust this will
 * not be an issue. This is a rather flexible hash with lots of options.
 * Currently, the only options supported are:
 *
 * - arbitrary output length (see \c SKEIN256_PARAMS)
 *
 * - free access to configuration block (in fact, \c SKEIN256_PARAMS is the
 *   configuration block, and a default one is used if not provided)
 *
 * \todo Expand Skein-256 parameters (add possible extra blocks, such as
 *       personalization, hmac, nonce, etc...). This will probably require
 *       a rewrite of the UBI subsystem which is rather hardcoded and rigid
 *       at the moment.
 *
 * \todo Rewrite the UBI code properly.
*/

struct SKEIN256_STATE;

/*! @see \c hash_function_alloc() */
ORDO_API struct SKEIN256_STATE * ORDO_CALLCONV
skein256_alloc(void);

/*! @see \c hash_function_init()
 *  @retval #ORDO_ARG if parameters were provided and requested an output
 *                       length of zero bytes.
*/
ORDO_API int ORDO_CALLCONV
skein256_init(struct SKEIN256_STATE *state,
              const struct SKEIN256_PARAMS *params);

/*! @see \c hash_function_update() */
ORDO_API void ORDO_CALLCONV
skein256_update(struct SKEIN256_STATE *state,
                const void *buffer,
                size_t len);

/*! @see \c hash_function_final()
 *  @remarks If no parameters were provided, the digest buffer must be at least
 *           32 bytes (256 bits) large. If parameters were provided, the buffer
 *           must be sufficiently large to store the output length requested
 *           by the parameters (note the parameters specify an output length
 *           in \b bits).
*/
ORDO_API void ORDO_CALLCONV
skein256_final(struct SKEIN256_STATE *state,
               void *digest);

/*! @see \c hash_function_free() */
ORDO_API void ORDO_CALLCONV
skein256_free(struct SKEIN256_STATE *state);

/*! @see \c hash_function_copy() */
ORDO_API void ORDO_CALLCONV
skein256_copy(struct SKEIN256_STATE *dst,
              const struct SKEIN256_STATE *src);

/*! @see \c hash_function_query() */
ORDO_API size_t ORDO_CALLCONV
skein256_query(int query, size_t value);

#ifdef __cplusplus
}
#endif

#endif
