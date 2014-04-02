/*===-- primitives/hash_functions/sha256.h -------------*- PUBLIC -*- H -*-===*/
/**
/// @file
/// @brief Primitive
///
/// The SHA-256 hash function, which produces a 256-bit digest.
**/
/*===----------------------------------------------------------------------===*/

#ifndef ORDO_SHA256_H
#define ORDO_SHA256_H

/** @cond **/
#include "ordo/common/interface.h"
/** @endcond **/

#include "ordo/primitives/hash_functions/hash_params.h"

#ifdef __cplusplus
extern "C" {
#endif

/*===----------------------------------------------------------------------===*/

struct SHA256_STATE;

/** @see \c hash_function_alloc()
**/
ORDO_PUBLIC
struct SHA256_STATE *sha256_alloc(void);

/** @see \c hash_function_init()
///
/// @remarks The \c params parameter is ignored.
**/
ORDO_PUBLIC
int sha256_init(struct SHA256_STATE *state,
                const void *params);

/** @see \c hash_function_update()
**/
ORDO_PUBLIC
void sha256_update(struct SHA256_STATE *state,
                   const void *buffer,
                   size_t len);

/** @see \c hash_function_final()
**/
ORDO_PUBLIC
void sha256_final(struct SHA256_STATE *state,
                  void *digest);

/** @see \c hash_function_free()
**/
ORDO_PUBLIC
void sha256_free(struct SHA256_STATE *state);

/** @see \c hash_function_copy()
**/
ORDO_PUBLIC
void sha256_copy(struct SHA256_STATE *dst,
                 const struct SHA256_STATE *src);

/** @see \c hash_function_query()
**/
ORDO_PUBLIC
size_t sha256_query(int query, size_t value);

/*===----------------------------------------------------------------------===*/

#ifdef __cplusplus
}
#endif

#endif
