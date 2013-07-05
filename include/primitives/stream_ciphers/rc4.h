#ifndef ORDO_RC4_H
#define ORDO_RC4_H

#include <primitives/primitives.h>

/******************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * @file rc4.h
 * @brief RC4 stream cipher.
 *
 * RC4 is a stream cipher, which accepts keys between 40 and 2048 bits (in
 * multiples of 8 bits only). It accepts a parameter consisting of the number
 * of initial keystream bytes to drop immediately after key schedule,
 * effectively  implementing RC4-drop[n]. If no drop parameter is passed,
 * the implementation drops 2048 bytes by default.
 *
 * @todo Better ABI translation for Windows assembler implementation(right now
 * it's a brute-force push/pop/swap to explicitly translate parameter passing)
*/

struct RC4_STATE;

/*! Allocates an RC4 state.
 @returns The allocated state, or nil on allocation failure.
*/
struct RC4_STATE* rc4_alloc();

/*! Initializes an RC4 state.
 @param state An allocated RC4 state.
 @param key The encryption key to use for encryption.
 @param key_len The length, in bytes, of the encryption key.
 @param params Points to an RC4 parameter structure.
 @return Returns \c #ORDO_SUCCESS on success, or \c #ORDO_KEY_LEN if the
         key length passed was invalid.
 @remarks The \c params parameter may be nil if no parameters are required.
*/
int rc4_init(struct RC4_STATE *state,
             const uint8_t *key,
             size_t key_len,
             const struct RC4_PARAMS *params);

/*! Encrypts or decrypts a buffer (as an array of bytes).
 @param state An initialized RC4 state.
 @param buffer The buffer to encrypt or decrypt.
 @param len The length, in bytes, of the buffer to process.
 @remarks This function will update the passed context, such that the keystream
          bytes generated to encrypt \c buffer will be discarded after use, and
          will not be produced again on subsequent calls.
*/
void rc4_update(struct RC4_STATE *state,
                uint8_t *buffer,
                size_t len);

/*! Frees an RC4 state.
 @param state An allocated RC4 state.
 @remarks Passing nil to this function is a no-op.
*/
void rc4_free(struct RC4_STATE *state);

/*! Performs a deep-copy of an RC4 state into another.
 @param dst The destination state.
 @param src The source state.
 @remarks The two states must have been initialized with the same parameters,
          unless specified otherwise in the documentation of \c RC4_PARAMS.
*/
void rc4_copy(struct RC4_STATE *dst, const struct RC4_STATE *src);

/*! Probes the RC4 stream cipher for its key length.
 @param key_len The suggested key length.
 @returns As RC4 supports keys between 40 and 2048 bits (5 and 256 bytes),
          this function will return \c key_len if it is within this interval,
          will return 5 if it is lower, and 256 if it is larger.
*/
size_t rc4_key_len(size_t key_len);

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

#ifdef __cplusplus
}
#endif

#endif
