#ifndef ORDO_BLOCK_CIPHERS_H
#define ORDO_BLOCK_CIPHERS_H

#include "primitives/block_ciphers/block_params.h"

/******************************************************************************/

/*!
 * @file block_ciphers.h
 * @brief Block cipher abstraction layer.
 *
 * <description here>
*/

#ifdef __cplusplus
extern "C" {
#endif

struct BLOCK_CIPHER;

/******************************************************************************/

/*! Returns the name of a block cipher primitive. */
const char* block_cipher_name(const struct BLOCK_CIPHER *primitive);

/******************************************************************************/

size_t block_cipher_count(void);

/*! The NullCipher block cipher. */
const struct BLOCK_CIPHER* NullCipher(void);

/*! The Threefish-256 block cipher. */
const struct BLOCK_CIPHER* Threefish256(void);

/*! The AES block cipher. */
const struct BLOCK_CIPHER* AES(void);

/******************************************************************************/

/*! Returns a block cipher primitive from a name. */
const struct BLOCK_CIPHER* block_cipher_by_name(const char *name);

/*! Returns a block cipher primitive from an ID. */
const struct BLOCK_CIPHER* block_cipher_by_id(size_t id);

/******************************************************************************/

void* block_cipher_alloc(const struct BLOCK_CIPHER *primitive);

int block_cipher_init(const struct BLOCK_CIPHER *primitive,
                      void *state,
                      const void *key,
                      size_t key_size,
                      const void *params);

void block_cipher_forward(const struct BLOCK_CIPHER *primitive,
                          void *state,
                          void *block);

void block_cipher_inverse(const struct BLOCK_CIPHER *primitive,
                          void *state,
                          void *block);

void block_cipher_free(const struct BLOCK_CIPHER *primitive,
                       void *state);

void block_cipher_copy(const struct BLOCK_CIPHER *primitive,
                       void *dst,
                       const void *src);
                       
size_t block_cipher_query(const struct BLOCK_CIPHER *primitive,
                          int query, size_t value);

#ifdef __cplusplus
}
#endif

#endif
