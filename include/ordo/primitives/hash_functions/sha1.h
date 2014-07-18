/*===-- primitives/hash_functions/sha1.h ---------------*- PUBLIC -*- H -*-===*/
/**
*** @file
*** @brief Primitive
***
*** The SHA-1 hash function, which produces a 160-bit digest.
**/
/*===----------------------------------------------------------------------===*/

#ifndef ORDO_SHA1_H
#define ORDO_SHA1_H

/** @cond **/
#include "ordo/common/interface.h"
/** @endcond **/

#include "ordo/primitives/hash_functions.h"

#ifdef __cplusplus
extern "C" {
#endif

/*===----------------------------------------------------------------------===*/

#define sha1_init                        ordo_sha1_init
#define sha1_update                      ordo_sha1_update
#define sha1_final                       ordo_sha1_final
#define sha1_query                       ordo_sha1_query
#define sha1_bsize                       ordo_sha1_bsize

/*===----------------------------------------------------------------------===*/

/** @see \c hash_init()
***
*** @remarks The \c params parameter is ignored.
**/
ORDO_PUBLIC
int sha1_init(struct SHA1_STATE *state,
              const void *params);

/** @see \c hash_update()
**/
ORDO_PUBLIC
void sha1_update(struct SHA1_STATE *state,
                 const void *buffer,
                 size_t len);

/** @see \c hash_final()
**/
ORDO_PUBLIC
void sha1_final(struct SHA1_STATE *state,
                void *digest);

/** @see \c hash_query()
**/
ORDO_PUBLIC
size_t sha1_query(int query, size_t value);

/** Gets the size in bytes of a \c SHA1_STATE.
***
*** @returns The size in bytes of the structure.
***
*** @remarks Binary compatibility layer.
**/
ORDO_PUBLIC
size_t sha1_bsize(void);

/*===----------------------------------------------------------------------===*/

#ifdef __cplusplus
}
#endif

#endif
