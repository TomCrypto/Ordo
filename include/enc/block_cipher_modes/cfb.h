#ifndef ORDO_CFB_H
#define ORDO_CFB_H

#include <enc/block_modes.h>

/******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * @file cfb.h
 * @brief CFB block mode of operation.
 *
 * The CFB mode generates a keystream by repeatedly encrypting an initialization vector and mixing in
 * the plaintext, effectively turning a block cipher into a stream cipher. As such, CFB mode requires no
 * padding, and the ciphertext size will always be equal to the plaintext size.
 *
 * Note that the CFB keystream depends on the plaintext fed into it, as opposed to OFB mode. This also
 * means the block cipher's inverse permutation is never used.
 *
 * \c cfb_final() accepts 0 as an argument for \c outlen, since by design the CFB mode of operation does not
 * produce any final data. However, if a valid pointer is passed, its value will be set to zero as expected.
*/

struct CFB_STATE;

struct CFB_STATE* cfb_alloc(const struct BLOCK_CIPHER* cipher, void* cipher_state);

int cfb_init(struct CFB_STATE *state, const struct BLOCK_CIPHER* cipher, void* cipher_state, const void* iv, size_t iv_len, int dir, const void* params);

void cfb_update(struct CFB_STATE *state, const struct BLOCK_CIPHER* cipher, void* cipher_state,
                const unsigned char* in, size_t inlen,
                unsigned char* out, size_t* outlen);

int cfb_final(struct CFB_STATE *state, const struct BLOCK_CIPHER* cipher, void* cipher_state, unsigned char* out, size_t* outlen);

void cfb_free(struct CFB_STATE *state, const struct BLOCK_CIPHER* cipher, void* cipher_state);

void cfb_copy(struct CFB_STATE *dst, const struct CFB_STATE *src, const struct BLOCK_CIPHER* cipher);

void cfb_set_mode(struct BLOCK_MODE* mode);

#ifdef __cplusplus
}
#endif

#endif
