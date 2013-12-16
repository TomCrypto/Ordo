#ifndef ORDO_THREEFISH256_H
#define ORDO_THREEFISH256_H

#include "ordo/internal/api.h"

#include "ordo/primitives/block_ciphers/block_params.h"

/******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/*! @file threefish256.h
 *
 * \brief Threefish-256 block cipher.
 *
 * Threefish-256 is a block cipher with a 256-bit block size and a 256-bit key
 * size. It also has an optional 128-bit tweak, which can be set through the
 * cipher parameters.
 *
 * The Threefish ciphers were originally designed to be used as a building
 * block for the Skein hash function family.
*/

struct THREEFISH256_STATE;

/*! @see \c block_cipher_alloc() */
ORDO_API struct THREEFISH256_STATE * ORDO_CALLCONV
threefish256_alloc(void);

/*! Initializes a Threefish-256 block cipher context.
 @param state An allocated Threefish-256 context.
 @param key A pointer to a 256-bit key, as a \c uint64_t[4] structure.
 @param key_len The key size, in bytes. Must be 32 (256 bits).
 @param params A pointer to a Threefish-256 parameter structure.
 @returns Returns \c #ORDO_SUCCESS on success, or \c #ORDO_KEY_LEN if the
          key size passed was invalid.
 @remarks The \c params parameter may be nil if no parameters are required.
*/
ORDO_API int ORDO_CALLCONV
threefish256_init(struct THREEFISH256_STATE *state,
                  const uint64_t *key, size_t key_len,
                  const struct THREEFISH256_PARAMS *params);

/*! @see \c block_cipher_forward() */
ORDO_API void ORDO_CALLCONV
threefish256_forward(struct THREEFISH256_STATE *state,
                     uint64_t *block);

/*! @see \c block_cipher_inverse() */
ORDO_API void ORDO_CALLCONV
threefish256_inverse(struct THREEFISH256_STATE *state,
                     uint64_t *block);

/*! @see \c block_cipher_free() */
ORDO_API void ORDO_CALLCONV
threefish256_free(struct THREEFISH256_STATE *state);

/*! @see \c block_cipher_copy() */
ORDO_API void ORDO_CALLCONV
threefish256_copy(struct THREEFISH256_STATE *dst,
                  const struct THREEFISH256_STATE *src);

/*! @see \c block_cipher_query() */
ORDO_API size_t ORDO_CALLCONV
threefish256_query(int query, size_t value);

/*! This function is \b stateless and is meant to be used when a context-free
 *  access to the raw cryptographic block cipher is required (such as in the
 *  Skein hash function family which uses Threefish inside its compression
 *  function).
 @remarks As such, this function is for internal use only and may change with
          implementation. It is not recommended to use it in external code.
 @remarks Performs the Threefish-256 key schedule.
 @internal
*/
ORDO_INTERNAL void ORDO_CALLCONV
threefish256_key_schedule(const uint64_t key[4],
                          const uint64_t tweak[2],
                                uint64_t subkeys[19][4]);

/*! See the \c threefish256_key_schedule() function.
 @remarks Computes the Threefish-256 forward permutation.
 @internal
*/
ORDO_INTERNAL void ORDO_CALLCONV
threefish256_forward_raw(uint64_t block[4],
                         uint64_t subkeys[19][4]);

/*! See the \c threefish256_key_schedule() function.
 @remarks Computes the Threefish-256 inverse permutation.
 @internal
*/
ORDO_INTERNAL void ORDO_CALLCONV
threefish256_inverse_raw(uint64_t block[4],
                         uint64_t subkeys[19][4]);

#ifdef __cplusplus
}
#endif

#endif
