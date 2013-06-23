#ifndef ORDO_AES_H
#define ORDO_AES_H

#include <primitives/primitives.h>

/******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file aes.h
 *
 * \brief AES block cipher.
 *
 * AES (Advanced Encryption Standard) is a block cipher. It has a 128-bit block
 * size and three possible key sizes, namely 128, 192 and 256 bits. It is based
 * on the Rijndael cipher and was selected as the official encryption standard
 * on November 2001 (FIPS 197).
 */

struct AES_STATE;

/*! Allocates and returns an uninitialized AES block cipher context.
 @returns The allocated context, or nil on allocation failure.
*/
struct AES_STATE* aes_alloc();

/*! Initializes an AES block cipher context.
 @param ctx An allocated AES context.
 @param key A pointer to a buffer containing the encryption key.
 @param keySize The key size, in bytes, to be read from \c key.
 @param params A pointer to an AES parameter structure.
 @returns Returns \c #ORDO_SUCCESS on success, \c #ORDO_KEY_SIZE if the
          key size passed was invalid, \c #ORDO_ARG if the round
          number provided in the parameters is invalid, or \c #ORDO_ALLOC
          if an allocation error occurs.
 @remarks The \c params parameter may be nil if no parameters are required.
*/
int aes_init(struct AES_STATE *state,
             const void* key, size_t keySize,
             const struct AES_PARAMS* params);

/*! Encrypts a 128-bit block (as an array of bytes).
 @param ctx An initialized AES context.
 @param block A pointer to the block to encrypt.
 @remarks This function is deterministic, as are all of the block cipher
          \c Forward and \c Inverse functions, and will not modify the
          state of the provided context.
*/
void aes_forward(struct AES_STATE *state,
                 uint8_t* block);

/*! Decrypts a 128-bit block (as an array of bytes).
 @param ctx An initialized AES context.
 @param block A pointer to the block to decrypt.
 @remarks See remarks for \c aes_forward().
*/
void aes_inverse(struct AES_STATE *state,
                 uint8_t* block);

/*! Frees the memory associated with an AES cipher context and securely erases
 *  sensitive context information such as key material.
 @param ctx An allocated AES context.
 @remarks The context need not have been initialized.
 @remarks Passing nil to this function is a no-op.
*/
void aes_free(struct AES_STATE *state);

void aes_copy(struct AES_STATE *dst,
              const struct AES_STATE *src);

/*! This function populates a block cipher object with the AES functions and
 *  attributes, and is meant for internal use.
 @param cipher A pointer to a block cipher object to populate.
 @remarks Once populated, the \c BLOCK_CIPHER struct can be freely used in the
          higher level \c enc_block interface.
 @remarks If you have issued a call to \c load_primitives(), this function has
          already been called and you may use the \c AES() function to access
          the underlying AES block cipher object.
 @see enc_block.h
 @internal
*/
void aes_set_primitive(struct BLOCK_CIPHER* cipher);

#ifdef __cplusplus
}
#endif

#endif
