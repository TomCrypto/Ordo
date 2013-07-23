#ifndef ORDO_MD5_H
#define ORDO_MD5_H

#include "primitives/hash_functions/hash_params.h"

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

/*! @see \c digest_alloc() */
struct MD5_STATE *md5_alloc(void);

/*! @see \c digest_init()
 *  @remarks The \c params parameter is ignored.
 *  @remarks This function always returns \c #ORDO_SUCCESS.
*/
int md5_init(struct MD5_STATE *state,
             const void *params);

/*! @see \c digest_update() */
void md5_update(struct MD5_STATE *state,
                const void *buffer,
                size_t len);

/*! @see \c digest_final()
 *  @remarks The digest buffer must be at least 16 bytes (128 bits) large.
*/
void md5_final(struct MD5_STATE *state,
               void *digest);

/*! @see \c digest_free() */
void md5_free(struct MD5_STATE *state);

/*! @see \c digest_copy() */
void md5_copy(struct MD5_STATE *dst,
              const struct MD5_STATE *src);
              
size_t md5_query(int query, size_t value);

#ifdef __cplusplus
}
#endif

#endif
