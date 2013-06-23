#ifndef ORDO_NULLCIPHER_H
#define ORDO_NULLCIPHER_H

#include <primitives/primitives.h>

/******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file nullcipher.h
 *
 * \brief Null Cipher block cipher.
 *
 * This cipher is only used to debug the library and does absolutely nothing,
 * in other words, it is the identity permutation. It accepts any key size but
 * does not even attempt to read the key, and has no parameters. Its block size
 * is 128 bits and is arbitrarily chosen.
 */

struct NULLCIPHER_STATE;

/*! Allocates and returns an uninitialized AES block cipher context.
 @returns The allocated context, or nil on allocation failure.
*/
struct NULLCIPHER_STATE* nullcipher_alloc();

/*! Initializes a NullCipher block cipher context.
 @param ctx An allocated NullCipher context.
 @param key A pointer to a buffer containing the encryption key.
 @param keySize The key size, in bytes, to be read from \c key.
 @param params Ignored.
 @returns Cannot fail and returns \c #ORDO_SUCCESS.
 @remarks This function does nothing.
*/
int nullcipher_init(struct NULLCIPHER_STATE *state,
                    const void* key, size_t keySize,
                    const void* params);

/*! Encrypts a 128-bit block.
 @param ctx An initialized NullCipher context.
 @param block A pointer to the block to encrypt.
 @remarks This function does nothing.
*/
void nullcipher_forward(struct NULLCIPHER_STATE *state,
                        void* block);

/*! Decrypts a 128-bit block.
 @param ctx An initialized NullCipher context.
 @param block A pointer to the block to decrypt.
 @remarks This function does nothing.
*/
void nullcipher_inverse(struct NULLCIPHER_STATE *state,
                        void* block);

/*! Frees the memory associated with a NullCipher cipher context.
 @param ctx An allocated NullCipher context.
 @remarks Passing nil to this function is a no-op.
*/
void nullcipher_free(struct NULLCIPHER_STATE *state);

void nullcipher_copy(struct NULLCIPHER_STATE *dst,
                     const struct NULLCIPHER_STATE *src);

/*! This function populates a block cipher object with the NullCipher
 *  functions and attributes, and is meant for internal use.
 @param cipher A pointer to a block cipher object to populate.
 @remarks Once populated, the \c BLOCK_CIPHER struct can be freely used in the
          higher level \c enc_block interface.
 @remarks If you have issued a call to \c load_primitives(), this function has
          already been called and you may use the \c NullCipher() function to
          access the underlying NullCipher block cipher object.
 @see enc_block.h
 @internal
*/
void nullcipher_set_primitive(struct BLOCK_CIPHER* cipher);

#ifdef __cplusplus
}
#endif

#endif
