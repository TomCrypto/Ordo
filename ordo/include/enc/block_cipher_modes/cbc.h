#ifndef ORDO_CBC_H
#define ORDO_CBC_H

#include <enc/block_modes.h>

/******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file cbc.h
 *
 * \brief CBC block cipher mode of operation.
 *
 * The CBC mode divides the input message into blocks of the cipher's block size, and encrypts them in a sequential
 * fashion, where each block depends on the previous one (and the first block depends on the initialization vector).
 * If the input message's length is not a multiple of the cipher's block size, a padding mechanism is enabled by
 * default which will pad the message to the correct length (and remove the extra data upon decryption). If
 * padding is explicitly disabled through the mode of operation's parameters, the input's length must be a multiple
 * of the cipher's block size.
 *
 * If padding is enabled, \c cbc_final() requires a valid pointer to be passed in the \c outlen parameter and will
 * always return a full blocksize of data, containing the last few ciphertext bytes containing the padding information.
 *
 * If padding is disabled, \c outlen is also required, and will return the number of unprocessed plaintext bytes in the
 * context. If this is any value other than zero, the function will also fail with \c ORDO_LEFTOVER.
 *
 * @see cbc.c
 */

struct CBC_STATE;

struct CBC_STATE* cbc_alloc(struct BLOCK_CIPHER* cipher, void* cipher_state);

int cbc_init(struct CBC_STATE *state, struct BLOCK_CIPHER* cipher, void* cipher_state, void* iv, int dir, struct CBC_PARAMS* params);

void cbc_update(struct CBC_STATE *state, struct BLOCK_CIPHER* cipher, void* cipher_state, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen);

int cbc_final(struct CBC_STATE *state, struct BLOCK_CIPHER* cipher, void* cipher_state, unsigned char* out, size_t* outlen);

void cbc_free(struct CBC_STATE *state, struct BLOCK_CIPHER* cipher, void* cipher_state);

void cbc_set_mode(struct BLOCK_MODE* mode);

#ifdef __cplusplus
}
#endif

#endif
