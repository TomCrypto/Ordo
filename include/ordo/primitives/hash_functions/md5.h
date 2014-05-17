/*===-- primitives/hash_functions/md5.h ----------------*- PUBLIC -*- H -*-===*/
/**
/// @file
/// @brief Primitive
///
/// The MD5 hash function, which produces a 128-bit digest.
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

struct MD5_STATE;

/** @see \c hash_function_init()
///
/// @remarks The \c params parameter is ignored.
**/
ORDO_PUBLIC
int md5_init(struct MD5_STATE *state,
             const void *params);

/** @see \c hash_function_update()
**/
ORDO_PUBLIC
void md5_update(struct MD5_STATE *state,
               const void *buffer,
               size_t len);

/** @see \c hash_function_final()
**/
ORDO_PUBLIC
void md5_final(struct MD5_STATE *state,
               void *digest);

/** @see \c hash_function_query()
**/
ORDO_PUBLIC
size_t md5_query(int query, size_t value);

/*===----------------------------------------------------------------------===*/

#ifdef __cplusplus
}
#endif

#endif
