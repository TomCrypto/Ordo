#ifndef ORDO_RC4_H
#define ORDO_RC4_H

#include <primitives/primitives.h>

/******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/*! @file rc4.h
 *
 * \brief RC4 stream cipher.
 *
 * RC4 is a stream cipher, which accepts keys between 40 and 2048 bits (in
 * multiples of 8 bits only). It accepts a parameter consisting of the number
 * of initial keystream bytes to drop immediately after key schedule,
 * effectively  implementing RC4-drop[n]. If no drop parameter is passed,
 * the implementation drops 2048 bytes by default.
 *
 * \todo Better ABI translation for Windows assembler implementation(right now
 * it's a brute-force push/pop/swap to explicitly translate parameter passing)
*/

struct RC4_STATE;

/*! Allocates and returns an uninitialized RC4 stream cipher context.
 @returns The allocated context, or nil on allocation failure.
*/
struct RC4_STATE* rc4_alloc();

/*! Initializes an RC4 stream cipher context.
 @param ctx An allocated RC4 context.
 @param key A pointer to a buffer containing the encryption key.
 @param keySize The size, in bytes, of the key to read from \c key.
 @param params A pointer to an RC4 parameter structure.
 @return Returns \c #ORDO_SUCCESS on success, or \c #ORDO_KEY_SIZE if the
         key size passed was invalid.
 @remarks The \c params parameter may be nil if no parameters are required.
*/
int rc4_init(struct RC4_STATE *state,
             const uint8_t* key, size_t keySize,
             const struct RC4_PARAMS* params);

/*! Encrypts or decrypts a buffer (as an array of bytes).
 @param ctx An initialized RC4 context.
 @param buffer A pointer to the buffer to encrypt or decrypt.
 @param len The length of the buffer pointed to by \c buffer.
 @remarks This function will update the passed context, such that the keystream
          bytes generated to encrypt \c buffer will be discarded after use, and
          will not be produced again on subsequent calls.
 @remarks Due to the nature of stream ciphers, encryption and decryption are
          identical, so this function serves both purposes.
*/
void rc4_update(struct RC4_STATE *state,
                uint8_t* buffer, size_t len);

/*! Frees the memory associated with an RC4 cipher context and securely erases
 *  sensitive context information such as state which may compromise the key.
 @param ctx An allocated RC4 context.
 @remarks The context need not have been initialized.
 @remarks Passing nil to this function is a no-op.
*/
void rc4_free(struct RC4_STATE *state);

void rc4_copy(struct RC4_STATE *dst, const struct RC4_STATE *src);

/*! This function populates a stream cipher object with the RC4 functions and
 *  attributes, and is meant for internal use.
 @param cipher A pointer to a stream cipher object to populate.
 @remarks Once populated, the \c STREAM_CIPHER struct can be freely used in
          the higher level \c enc_stream interface.
 @remarks If you have issued a call to \c load_primitives(), this function has
          already been called and you may use the \c RC4() function to access
          the underlying RC4 stream cipher object.
 @see enc_stream.h
 @internal
*/
void rc4_set_primitive(struct STREAM_CIPHER* cipher);

size_t rc4_key_len(size_t key_len);

#ifdef __cplusplus
}
#endif

#endif
