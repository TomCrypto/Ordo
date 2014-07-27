/*===-- primitives/hash_functions/sha256.h -------------*- PUBLIC -*- H -*-===*/
/**
*** @file
*** @brief Primitive
***
*** The SHA-256 hash function, which produces a 256-bit digest.
**/
/*===----------------------------------------------------------------------===*/

#ifndef ORDO_SHA256_H
#define ORDO_SHA256_H

/** @cond **/
#include "ordo/common/interface.h"
/** @endcond **/

#include "ordo/primitives/hash_functions.h"

#ifdef __cplusplus
extern "C" {
#endif

/*===----------------------------------------------------------------------===*/

#define sha256_init                      ordo_sha256_init
#define sha256_update                    ordo_sha256_update
#define sha256_final                     ordo_sha256_final
#define sha256_limits                    ordo_sha256_limits
#define sha256_bsize                     ordo_sha256_bsize

/*===----------------------------------------------------------------------===*/

/** @see \c hash_init()
***
*** @remarks The \c params parameter is ignored.
**/
ORDO_PUBLIC
int sha256_init(struct SHA256_STATE *state,
                const void *params);

/** @see \c hash_update()
**/
ORDO_PUBLIC
void sha256_update(struct SHA256_STATE *state,
                   const void *buffer,
                   size_t len);

/** @see \c hash_final()
**/
ORDO_PUBLIC
void sha256_final(struct SHA256_STATE *state,
                  void *digest);

/** @see \c hash_limits()
**/
ORDO_PUBLIC
int sha256_limits(struct HASH_LIMITS *limits);

/** Gets the size in bytes of a \c SHA256_STATE.
***
*** @returns The size in bytes of the structure.
***
*** @remarks Binary compatibility layer.
**/
ORDO_PUBLIC
size_t sha256_bsize(void);

/*===----------------------------------------------------------------------===*/

#ifdef __cplusplus
}
#endif

#endif
