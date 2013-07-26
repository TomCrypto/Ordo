#ifndef ORDO_SHA256_H
#define ORDO_SHA256_H

#include "ordo/primitives/hash_functions/hash_params.h"

/******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * @file sha256.h
 * @brief SHA-256 hash function.
 *
 * The SHA-256 hash function, which produces a 256-bit digest.
*/

struct SHA256_STATE;

/*! @see \c hash_function_alloc() */
struct SHA256_STATE *sha256_alloc(void);

/*! @see \c hash_function_init()
 *  @remarks The \c params parameter is ignored.
*/
int sha256_init(struct SHA256_STATE *state,
                const void *params);

/*! @see \c hash_function_update() */
void sha256_update(struct SHA256_STATE *state,
                   const void *buffer,
                   size_t len);

/*! @see \c hash_function_final()
 *  @remarks The digest buffer must be at least 32 bytes (256 bits) large.
*/
void sha256_final(struct SHA256_STATE *state,
                  void *digest);

/*! @see \c hash_function_free() */
void sha256_free(struct SHA256_STATE *state);

/*! @see \c hash_function_copy() */
void sha256_copy(struct SHA256_STATE *dst,
                 const struct SHA256_STATE *src);

/*! @see \c hash_function_query() */         
size_t sha256_query(int query, size_t value);

#ifdef __cplusplus
}
#endif

#endif
