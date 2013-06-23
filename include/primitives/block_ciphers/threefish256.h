#ifndef ORDO_THREEFISH256_H
#define ORDO_THREEFISH256_H

#include <primitives/primitives.h>

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

/*! Allocates and returns an uninitialized Threefish-256 block cipher context.
 @returns The allocated context, or nil on allocation failure.
*/
struct THREEFISH256_STATE* threefish256_alloc();

/*! Initializes a Threefish-256 block cipher context.
 @param ctx An allocated Threefish-256 context.
 @param key A pointer to a 256-bit key, as a \c uint64_t[4] structure.
 @param keySize The key size, in bytes. Must be 32 (256 bits).
 @param params A pointer to a Threefish-256 parameter structure.
 @returns Returns \c #ORDO_SUCCESS on success, or \c #ORDO_KEY_SIZE if the
          key size passed was invalid.
 @remarks The \c params parameter may be nil if no parameters are required.
*/
int threefish256_init(struct THREEFISH256_STATE *state,
                      const uint64_t* key, size_t keySize,
                      const struct THREEFISH256_PARAMS* params);

/*! Encrypts a 256-bit block (as a \c uint64_t[4] structure).
 @param ctx An initialized Threefish-256 context.
 @param block A pointer to the block to encrypt.
 @remarks This function is deterministic, as are all of the block cipher
          \c Forward and \c Inverse functions, and will not modify the
          state of the provided context.
*/
void threefish256_forward(struct THREEFISH256_STATE *state,
                          uint64_t* block);

/*! Decrypts a 256-bit block (as a \c uint64_t[4] structure).
 @param ctx An initialized Threefish-256 context.
 @param block A pointer to the block to decrypt.
 @remarks See remarks for \c threefish256_forward().
*/
void threefish256_inverse(struct THREEFISH256_STATE *state,
                          uint64_t* block);

/*! Frees the memory associated with a Threefish-256 cipher context and
 *  securely erases sensitive context information such as key material.
 @param ctx An allocated Threefish-256 context.
 @remarks The context need not have been initialized.
 @remarks Passing nil to this function is a no-op.
*/
void threefish256_free(struct THREEFISH256_STATE *state);

void threefish256_copy(struct THREEFISH256_STATE *dst,
                       const struct THREEFISH256_STATE *src);

/*! This function populates a block cipher object with the Threefish-256
 *  functions and attributes, and is meant for internal use.
 @param cipher A pointer to a block cipher object to populate.
 @remarks Once populated, the \c BLOCK_CIPHER struct can be freely used in the
          higher level \c enc_block interface.
 @remarks If you have issued a call to \c load_primitives(), this function has
          already been called and you may use the \c Threefish256() function to
          access the underlying Threefish-256 block cipher object.
 @see enc_block.h
 @internal
*/
void threefish256_set_primitive(struct BLOCK_CIPHER* cipher);

/*! This function is \b stateless and is meant to be used when a context-free
 *  access to the raw cryptographic block cipher is required (such as in the
 *  Skein hash function family which uses Threefish inside its compression
 *  function).
 @remarks As such, this function is for internal use only and may change with
          implementation. It is not recommended to use it in external code.
 @remarks Performs the Threefish-256 key schedule.
 @internal
*/
void threefish256_key_schedule(const uint64_t key[4],
                               const uint64_t tweak[2],
                                     uint64_t subkeys[19][4]);

/*! See the \c threefish256_key_schedule() function.
 @remarks Computes the Threefish-256 forward permutation.
 @internal
*/
void threefish256_forward_raw(uint64_t block[4],
                                     uint64_t subkeys[19][4]);

/*! See the \c threefish256_key_schedule() function.
 @remarks Computes the Threefish-256 inverse permutation.
 @internal
*/
void threefish256_inverse_raw(uint64_t block[4],
                                     uint64_t subkeys[19][4]);

#ifdef __cplusplus
}
#endif

#endif
