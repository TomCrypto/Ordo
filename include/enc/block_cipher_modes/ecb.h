#ifndef ORDO_ECB_H
#define ORDO_ECB_H

#include <enc/block_modes.h>

/******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file ecb.h
 *
 * \brief ECB block cipher mode of operation.
 *
 * The ECB mode divides the input message into blocks of the cipher's block size, and encrypts them individually.
 * If the input message's length is not a multiple of the cipher's block size, a padding mechanism is enabled by
 * default which will pad the message to the correct length (and remove the extra data upon decryption). If
 * padding is explicitly disabled through the mode of operation's parameters, the input's length must be a multiple
 * of the cipher's block size.
 *
 * If padding is enabled, \c ECB_Final() requires a valid pointer to be passed in the \c outlen parameter and will
 * always return a full blocksize of data, containing the last few ciphertext bytes containing the padding information.
 *
 * If padding is disabled, \c outlen is also required, and will return the number of unprocessed plaintext bytes in the
 * context. If this is any value other than zero, the function will also fail with \c ORDO_LEFTOVER.
 *
 *
 * The ECB mode does not require an initialization vector.
 *
 * Note that the ECB mode is insecure in almost all situations and is not recommended for use.
 *
 * @see ecb.c
 */

struct ECB_STATE;

struct ECB_STATE* ecb_alloc(struct BLOCK_CIPHER* cipher, void* cipher_state);

int ecb_init(struct ECB_STATE *state, struct BLOCK_CIPHER* cipher, void* cipher_state, void* iv, int dir, struct ECB_PARAMS* params);

void ecb_update(struct ECB_STATE *state, struct BLOCK_CIPHER* cipher, void* cipher_state, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen);

int ecb_final(struct ECB_STATE *state, struct BLOCK_CIPHER* cipher, void* cipher_state, unsigned char* out, size_t* outlen);

void ecb_free(struct ECB_STATE *state, struct BLOCK_CIPHER* cipher, void* cipher_state);

void ecb_set_mode(struct BLOCK_MODE* mode);

#ifdef __cplusplus
}
#endif

#endif
