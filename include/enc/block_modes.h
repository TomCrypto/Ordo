#ifndef ORDO_BLOCK_MODES_H
#define ORDO_BLOCK_MODES_H

#include <enc/block_cipher_modes/mode_params.h>
#include <primitives/primitives.h>

/******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * @file block_modes.h
 * @brief Block mode of operation abstraction layer.
 *
 * This declares all the block modes of operation in the library, abstracting
 * them through higher level interfaces.
*/

typedef void* (* BLOCK_MODE_ALLOC)(const struct BLOCK_CIPHER*,
                                   void*);

typedef int (* BLOCK_MODE_INIT)(void*, 
                                const struct BLOCK_CIPHER*,
                                void*,
                                const void*,
                                size_t,
                                int,
                                const void*);

typedef void (* BLOCK_MODE_UPDATE)(void*,
                                   const struct BLOCK_CIPHER*,
                                   void*,
                                   const void*,
                                   size_t,
                                   void*,
                                   size_t*);

typedef int (* BLOCK_MODE_FINAL)(void*,
                                 const struct BLOCK_CIPHER*,
                                 void*,
                                 void*,
                                 size_t*);

typedef void (* BLOCK_MODE_FREE)(void*,
                                 const struct BLOCK_CIPHER*,
                                 void*);

typedef void (* BLOCK_MODE_COPY)(void*,
                                 const void*,
                                 const struct BLOCK_CIPHER*);

struct BLOCK_MODE;

void make_block_mode(struct BLOCK_MODE *mode,
                     BLOCK_MODE_ALLOC alloc,
                     BLOCK_MODE_INIT init,
                     BLOCK_MODE_UPDATE update,
                     BLOCK_MODE_FINAL final,
                     BLOCK_MODE_FREE free,
                     BLOCK_MODE_COPY copy,
                     const char *name);

/******************************************************************************/

const char* block_mode_name(const struct BLOCK_MODE *mode);

/******************************************************************************/

/*! Loads all block modes of operation provided by the library.
 @remarks This must be called before you may use \c ECB(), \c CBC(), etc...
          or the helper functions \c block_mode_by_name() and
          \c block_mode_by_id().
*/
void load_block_modes(void);

/*! The ECB (Electronic CodeBook) mode of operation. */
const struct BLOCK_MODE* ECB(void);
/*! The CBC (Ciphertext Block Chaining) mode of operation. */
const struct BLOCK_MODE* CBC(void);
/*! The CTR (CounTeR) mode of operation. */
const struct BLOCK_MODE* CTR(void);
/*! The CFB (Cipher FeedBack) mode of operation. */
const struct BLOCK_MODE* CFB(void);
/*! The OFB (Output FeedBack) mode of operation. */
const struct BLOCK_MODE* OFB(void);

/******************************************************************************/

/*! Gets a block cipher mode of operation from a name. */
const struct BLOCK_MODE* block_mode_by_name(const char* name);

/*! Gets a block cipher mode of operation from an ID. */
const struct BLOCK_MODE* block_mode_by_id(size_t id);

/******************************************************************************/

void* block_mode_alloc(const struct BLOCK_MODE* mode,
                       const struct BLOCK_CIPHER *cipher,
                       void *cipher_state);

int block_mode_init(const struct BLOCK_MODE *mode,
                    void *state,
                    const struct BLOCK_CIPHER *cipher,
                    void *cipher_state,
                    const void *iv,
                    size_t iv_len,
                    int direction,
                    const void *params);

void block_mode_update(const struct BLOCK_MODE *mode,
                       void *state,
                       const struct BLOCK_CIPHER *cipher,
                       void *cipher_state,
                       const void *in,
                       size_t inlen,
                       void *out,
                       size_t *outlen);

int block_mode_final(const struct BLOCK_MODE *mode,
                     void *state,
                     const struct BLOCK_CIPHER *cipher,
                     void* cipher_state,
                     void* out,
                     size_t *outlen);

void block_mode_free(const struct BLOCK_MODE *mode,
                     void *state,
                     const struct BLOCK_CIPHER *cipher,
                     void *cipher_state);

void block_mode_copy(const struct BLOCK_MODE *mode,
                     const struct BLOCK_CIPHER *cipher,
                     void *dst,
                     const void *src);

#ifdef __cplusplus
}
#endif

#endif
