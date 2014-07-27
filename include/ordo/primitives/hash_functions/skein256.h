/*===-- primitives/hash_functions/skein256.h -----------*- PUBLIC -*- H -*-===*/
/**
*** @file
*** @brief Primitive
***
*** This is  the Skein-256 hash function,  which produces a 256-bit  digest by
*** default (but has  parameters to output a longer digest)  and has a 256-bit
*** internal state.  This implementation supports  messages up to a  length of
*** 2^64 - 1 bytes  instead of the 2^96 - 1 available, but  we trust this will
*** not be  an issue.  This is a  rather flexible hash  with lots  of options.
*** Currently, the only options supported are:
***
*** - free access to  configuration block (in fact, \c  SKEIN256_PARAMS is the
***   configuration block, and a default one is used if not provided) with the
***   exception of the output length which must remain 256 bits.
***
*** Note arbitrary output length used to be supported, but is no longer, since
*** parameters should not leak through the interface, and this feature is also
*** available in a more generic way via key stretching modules such as HKDF or
*** DRBG.
**/
/*===----------------------------------------------------------------------===*/

#ifndef ORDO_SKEIN256_H
#define ORDO_SKEIN256_H

/** @cond **/
#include "ordo/common/interface.h"
/** @endcond **/

#include "ordo/primitives/hash_functions.h"

#ifdef __cplusplus
extern "C" {
#endif

/*===----------------------------------------------------------------------===*/

#define skein256_init                    ordo_skein256_init
#define skein256_update                  ordo_skein256_update
#define skein256_final                   ordo_skein256_final
#define skein256_limits                  ordo_skein256_limits
#define skein256_bsize                    ordo_skein256_bsize

/*===----------------------------------------------------------------------===*/

/** @see \c hash_init()
***
*** @retval #ORDO_ARG if parameters were  provided, but  requested  an  output
***                      length of zero bytes.
**/
ORDO_PUBLIC
int skein256_init(struct SKEIN256_STATE *state,
                  const struct SKEIN256_PARAMS *params);

/** @see \c hash_update()
**/
ORDO_PUBLIC
void skein256_update(struct SKEIN256_STATE *state,
                     const void *buffer,
                     size_t len);

/** @see \c hash_final()
**/
ORDO_PUBLIC
void skein256_final(struct SKEIN256_STATE *state,
                    void *digest);

/** @see \c hash_limits()
**/
ORDO_PUBLIC
int skein256_limits(struct HASH_LIMITS *limits);

/** Gets the size in bytes of a \c SKEIN256_STATE.
***
*** @returns The size in bytes of the structure.
***
*** @remarks Binary compatibility layer.
**/
ORDO_PUBLIC
size_t skein256_bsize(void);

/*===----------------------------------------------------------------------===*/

#ifdef __cplusplus
}
#endif

#endif
