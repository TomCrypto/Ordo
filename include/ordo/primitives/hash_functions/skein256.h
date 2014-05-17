/*===-- primitives/hash_functions/skein256.h -----------*- PUBLIC -*- H -*-===*/
/**
/// @file
/// @brief Primitive
///
/// This is  the Skein-256 hash function,  which produces a 256-bit  digest by
/// default (but has  parameters to output a longer digest)  and has a 256-bit
/// internal state.  This implementation supports  messages up to a  length of
/// 2^64 - 1 bytes  instead of the 2^96 - 1 available, but  we trust this will
/// not be  an issue.  This is a  rather flexible hash  with lots  of options.
/// Currently, the only options supported are:
///
/// - arbitrary output length (see \c SKEIN256_PARAMS)
///
/// - free access to  configuration block (in fact, \c  SKEIN256_PARAMS is the
///   configuration block, and a default one is used if not provided)
**/
/*===----------------------------------------------------------------------===*/

#ifndef ORDO_SKEIN256_H
#define ORDO_SKEIN256_H

/** @cond **/
#include "ordo/common/interface.h"
/** @endcond **/

#include "ordo/primitives/hash_functions/hash_params.h"

#ifdef __cplusplus
extern "C" {
#endif

/*===----------------------------------------------------------------------===*/

struct SKEIN256_STATE;

/** @see \c hash_function_init()
///
/// @retval #ORDO_ARG if parameters were  provided, but  requested  an  output
///                      length of zero bytes.
**/
ORDO_PUBLIC
int skein256_init(struct SKEIN256_STATE *state,
                  const struct SKEIN256_PARAMS *params);

/** @see \c hash_function_update()
**/
ORDO_PUBLIC
void skein256_update(struct SKEIN256_STATE *state,
                     const void *buffer,
                     size_t len);

/** @see \c hash_function_final()
///
/// @remarks If no parameters are provided, the digest buffer must be at least
///          32 bytes (256 bits) large. If parameters are provided, the buffer
///          must be sufficiently large to store the output length required by
///          the parameters (note the parameters specified an output length in
///          \b bits).
**/
ORDO_PUBLIC
void skein256_final(struct SKEIN256_STATE *state,
                    void *digest);

/** @see \c hash_function_query()
**/
ORDO_PUBLIC
size_t skein256_query(int query, size_t value);

/*===----------------------------------------------------------------------===*/

#ifdef __cplusplus
}
#endif

#endif
