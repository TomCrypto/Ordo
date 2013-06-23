#ifndef ORDO_CTR_H
#define ORDO_CTR_H

#include <enc/block_modes.h>

/******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * @file ctr.h
 * @brief CTR block mode of operation.
 *
 * The CTR mode generates a keystream by repeatedly encrypting a counter starting from some
 * initialization vector, effectively turning a block cipher into a stream cipher. As such,
 * CTR mode requires no padding, and outlen will always be equal to inlen.
 *
 * Note that the CTR keystream is independent of the plaintext, and is also spatially coherent
 * (using a given initialization vector on a len-byte message will "use up" len bytes of the
 * keystream) so care must be taken to avoid reusing the initialization vector in an insecure
 * way. This also means the block cipher's inverse permutation is never used.
 *
 * \c ctr_final() accepts 0 as an argument for \c outlen, since by design the CTR mode of operation does not
 * produce any final data. However, if a valid pointer is passed, its value will be set to zero as expected.
*/

struct CTR_STATE;

struct CTR_STATE* ctr_alloc(const struct BLOCK_CIPHER* cipher, void* cipher_state);

int ctr_init(struct CTR_STATE *state, const struct BLOCK_CIPHER* cipher, void* cipher_state, const void* iv, size_t iv_len, int dir, const void* params);

void ctr_update(struct CTR_STATE *state, const struct BLOCK_CIPHER* cipher, void* cipher_state,
                const unsigned char* in, size_t inlen,
                unsigned char* out, size_t* outlen);

int ctr_final(struct CTR_STATE *state, const struct BLOCK_CIPHER* cipher, void* cipher_state, unsigned char* out, size_t* outlen);

void ctr_free(struct CTR_STATE *state, const struct BLOCK_CIPHER* cipher, void* cipher_state);

void ctr_copy(struct CTR_STATE *dst, const struct CTR_STATE *src, const struct BLOCK_CIPHER* cipher);

void ctr_set_mode(struct BLOCK_MODE* mode);

#ifdef __cplusplus
}
#endif

#endif
