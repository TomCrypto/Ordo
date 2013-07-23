#ifndef ORDO_SKEIN256_H
#define ORDO_SKEIN256_H

#include "primitives/hash_functions/hash_params.h"

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

/*! @see \c digest_alloc() */
struct SKEIN256_STATE* skein256_alloc(void);

/*! @see \c digest_init()
 *  @retval #ORDO_ARG if parameters were provided and requested an output
 *                       length of zero bytes.
*/
int skein256_init(struct SKEIN256_STATE *state,
                  const struct SKEIN256_PARAMS *params);

/*! @see \c digest_update() */
void skein256_update(struct SKEIN256_STATE *state,
                     const void *buffer,
                     size_t len);

/*! @see \c digest_final()
 *  @remarks If no parameters were provided, the digest buffer must be at least
 *           32 bytes (256 bits) large. If parameters were provided, the buffer
 *           must be sufficiently large to store the output length requested
 *           by the parameters (note the parameters specify an output length
 *           in \b bits).
*/
void skein256_final(struct SKEIN256_STATE *state,
                    void *digest);

/*! @see \c digest_free() */
void skein256_free(struct SKEIN256_STATE *state);

/*! @see \c digest_copy() */
void skein256_copy(struct SKEIN256_STATE *dst,
                   const struct SKEIN256_STATE *src);

size_t skein256_query(int query, size_t value);

#ifdef __cplusplus
}
#endif

#endif
