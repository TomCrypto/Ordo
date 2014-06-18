/*===-- primitives/hash_functions/md5.h ----------------*- PUBLIC -*- H -*-===*/
/**
*** @file
*** @brief Primitive
***
*** The MD5 hash function, which produces a 128-bit digest.
**/
/*===----------------------------------------------------------------------===*/

#ifndef ORDO_MD5_H
#define ORDO_MD5_H

/** @cond **/
#include "ordo/common/interface.h"
/** @endcond **/

#include "ordo/primitives/hash_functions/hash_params.h"

#ifdef __cplusplus
extern "C" {
#endif

/*===----------------------------------------------------------------------===*/

#define md5_init                         ordo_md5_init
#define md5_update                       ordo_md5_update
#define md5_final                        ordo_md5_final
#define md5_query                        ordo_md5_query
#define md5_bsize                        ordo_md5_bsize

/*===----------------------------------------------------------------------===*/

/** @see \c hash_init()
***
*** @remarks The \c params parameter is ignored.
**/
ORDO_PUBLIC
int md5_init(struct MD5_STATE *state,
             const void *params);

/** @see \c hash_update()
**/
ORDO_PUBLIC
void md5_update(struct MD5_STATE *state,
               const void *buffer,
               size_t len);

/** @see \c hash_final()
**/
ORDO_PUBLIC
void md5_final(struct MD5_STATE *state,
               void *digest);

/** @see \c hash_query()
**/
ORDO_PUBLIC
size_t md5_query(int query, size_t value);

/** Gets the size in bytes of an \c MD5_STATE.
***
*** @returns The size in bytes of the structure.
***
*** @remarks Binary compatibility layer.
**/
ORDO_PUBLIC
size_t md5_bsize(void);

/*===----------------------------------------------------------------------===*/

#ifdef __cplusplus
}
#endif

#endif
