#ifndef ORDO_BLOCK_MODES_H
#define ORDO_BLOCK_MODES_H

#include <enc/block_cipher_modes/mode_params.h>
#include <primitives/primitives.h>

/******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/* Block cipher mode of operation interface function prototypes. */
typedef void* (* BLOCK_MODE_ALLOC)(struct BLOCK_CIPHER*, void*);
typedef int (* BLOCK_MODE_INIT)(void*, struct BLOCK_CIPHER*, void*, void*, int, void*);
typedef void (* BLOCK_MODE_UPDATE)(void*, struct BLOCK_CIPHER*, void*,
                                          void*, size_t, void*, size_t*);
typedef int (* BLOCK_MODE_FINAL)(void*, struct BLOCK_CIPHER*, void*, void*, size_t*);
typedef void (* BLOCK_MODE_FREE)(void*, struct BLOCK_CIPHER*, void*);

struct BLOCK_MODE;

/*! Loads all encryption modes of operation. This must be called before you may use \c ECB(), \c CBC(), etc... or the
 * helper functions \c block_mode_by_name() and \c block_mode_by_id(). */
void encryptLoad();

/*! The ECB (Electronic CodeBook) mode of operation. */
struct BLOCK_MODE* ECB();
/*! The CBC (Ciphertext Block Chaining) mode of operation. */
struct BLOCK_MODE* CBC();
/*! The CTR (CounTeR) mode of operation. */
struct BLOCK_MODE* CTR();
/*! The CFB (Cipher FeedBack) mode of operation. */
struct BLOCK_MODE* CFB();
/*! The OFB (Output FeedBack) mode of operation. */
struct BLOCK_MODE* OFB();

/*! Gets a block cipher mode of operation object from a name. */
struct BLOCK_MODE* block_mode_by_name(char* name);

/*! Gets a block cipher mode of operation object from an ID. */
struct BLOCK_MODE* block_mode_by_id(size_t id);

const char* block_mode_name(struct BLOCK_MODE *mode);

void make_block_mode(struct BLOCK_MODE *mode,
                       BLOCK_MODE_ALLOC alloc, BLOCK_MODE_INIT init, BLOCK_MODE_UPDATE update,
                       BLOCK_MODE_FINAL final, BLOCK_MODE_FREE free, char *name);

/* BLOCK MODE ABSTRACTION LAYER. */

void* block_mode_alloc(struct BLOCK_MODE* mode, struct BLOCK_CIPHER *cipher, void* cipher_ctx);

int block_mode_init(struct BLOCK_MODE *mode, void *ctx, struct BLOCK_CIPHER *cipher, void* cipher_ctx,
                        void* iv, int dir, void* params);

void block_mode_update(struct BLOCK_MODE *mode, void *ctx, struct BLOCK_CIPHER *cipher, void* cipher_ctx,
                           void* in, size_t inlen,
                           void* out, size_t* outlen);

int block_mode_final(struct BLOCK_MODE *mode, void *ctx, struct BLOCK_CIPHER *cipher, void* cipher_ctx,
                         void* out, size_t* outlen);

void block_mode_free(struct BLOCK_MODE *mode, void *ctx, struct BLOCK_CIPHER *cipher, void* cipher_ctx);

#ifdef __cplusplus
}
#endif

#endif
