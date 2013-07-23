#ifndef ORDO_STREAM_CIPHERS_H
#define ORDO_STREAM_CIPHERS_H

#include "primitives/stream_ciphers/stream_params.h"

/******************************************************************************/

/*!
 * @file stream_ciphers.h
 * @brief Stream cipher abstraction layer.
 *
 * <description here>
*/

#ifdef __cplusplus
extern "C" {
#endif

struct STREAM_CIPHER;

/******************************************************************************/

/*! Returns the name of a stream cipher primitive. */
const char* stream_cipher_name(const struct STREAM_CIPHER *primitive);

/******************************************************************************/

size_t stream_cipher_count(void);

/*! The RC4 stream cipher. */
const struct STREAM_CIPHER* RC4(void);

/******************************************************************************/

/*! Returns a stream cipher primitive from a name. */
const struct STREAM_CIPHER* stream_cipher_by_name(const char *name);

/*! Returns a stream cipher primitive from an ID. */
const struct STREAM_CIPHER* stream_cipher_by_id(size_t id);

/******************************************************************************/

void* stream_cipher_alloc(const struct STREAM_CIPHER *primitive);

int stream_cipher_init(const struct STREAM_CIPHER *primitive,
                       void* state,
                       const void *key,
                       size_t key_size,
                       const void *params);

void stream_cipher_update(const struct STREAM_CIPHER *primitive,
                          void* state,
                          void *buffer,
                          size_t size);

void stream_cipher_free(const struct STREAM_CIPHER *primitive,
                        void *state);

void stream_cipher_copy(const struct STREAM_CIPHER *primitive,
                        void *dst,
                        const void *src);

size_t stream_cipher_query(const struct STREAM_CIPHER *primitive,
                           int query, size_t key_len);

#ifdef __cplusplus
}
#endif

#endif
