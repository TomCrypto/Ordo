#ifndef ORDO_HASH_FUNCTIONS_H
#define ORDO_HASH_FUNCTIONS_H

#include "primitives/hash_functions/hash_params.h"

/******************************************************************************/

/*!
 * @file hash_functions.h
 * @brief Hash function abstraction layer.
 *
 * <description here>
*/

#ifdef __cplusplus
extern "C" {
#endif

struct HASH_FUNCTION;

/******************************************************************************/

/*! Returns the name of a hash function primitive. */
const char* hash_function_name(const struct HASH_FUNCTION *primitive);

/******************************************************************************/

size_t hash_function_count(void);

/*! The SHA256 hash function. */
const struct HASH_FUNCTION* SHA256(void);

/*! The MD5 hash function. */
const struct HASH_FUNCTION* MD5(void);

/*! The Skein-256 hash function. */
const struct HASH_FUNCTION* Skein256(void);

/******************************************************************************/

/*! Returns a hash function primitive from a name. */
const struct HASH_FUNCTION* hash_function_by_name(const char *name);

/*! Returns a hash function primitive from an ID. */
const struct HASH_FUNCTION* hash_function_by_id(size_t id);

/******************************************************************************/

void* hash_function_alloc(const struct HASH_FUNCTION *primitive);

int hash_function_init(const struct HASH_FUNCTION *primitive,
                       void *state,
                       const void *params);

void hash_function_update(const struct HASH_FUNCTION *primitive,
                          void *state,
                          const void *buffer,
                          size_t size);

void hash_function_final(const struct HASH_FUNCTION *primitive,
                         void *state,
                         void *digest);

void hash_function_free(const struct HASH_FUNCTION *primitive,
                        void *state);

void hash_function_copy(const struct HASH_FUNCTION *primitive,
                        void *dst,
                        const void *src);

size_t hash_function_query(const struct HASH_FUNCTION *primitive,
                           int query, size_t value);

#ifdef __cplusplus
}
#endif

#endif
