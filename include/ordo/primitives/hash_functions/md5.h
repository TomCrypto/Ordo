#ifndef ORDO_MD5_H
#define ORDO_MD5_H

#include "ordo/primitives/hash_functions/hash_params.h"

/******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * @file md5.h
 * @brief MD5 hash function.
 *
 * The MD5 hash function, which produces a 128-bit digest.
*/

struct MD5_STATE;

/*! @see \c hash_function_alloc() */
struct MD5_STATE *md5_alloc(void);

/*! @see \c hash_function_init()
 *  @remarks The \c params parameter is ignored.
*/
int md5_init(struct MD5_STATE *state,
             const void *params);

/*! @see \c hash_function_update() */
void md5_update(struct MD5_STATE *state,
                const void *buffer,
                size_t len);

/*! @see \c hash_function_final()
 *  @remarks The digest buffer must be at least 16 bytes (128 bits) large.
*/
void md5_final(struct MD5_STATE *state,
               void *digest);

/*! @see \c hash_function_free() */
void md5_free(struct MD5_STATE *state);

/*! @see \c hash_function_copy() */
void md5_copy(struct MD5_STATE *dst,
              const struct MD5_STATE *src);

/*! @see \c hash_function_query() */
size_t md5_query(int query, size_t value);

#ifdef __cplusplus
}
#endif

#endif
