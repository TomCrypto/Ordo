#ifndef ordo_h
#define ordo_h

/**
 * @file ordo.h
 *
 * \brief Ordo high-level API.
 *
 * This is the highest-level API for Ordo, which forgoes the use of cryptographic contexts completely,
 * resulting in more concise code at the cost of reduced flexibility.
 *
 * @see ordo.c
 */

#include <common/ordotypes.h>
#include <primitives/primitives.h>
#include <enc/enc_block.h>
#include <enc/enc_stream.h>
#include <random/random.h>

/*! Loads Ordo - this calls all the load functions in the different interfaces (primitives, encrypt, etc...). */
void ordoLoad();

/*! This function encrypts a buffer of a given length with the provided parameters.
 \param in This points to a plaintext buffer.
 \param inlen This contains the number of bytes of plaintext.
 \param out This points to the buffer to which to write the ciphertext.
 \param outlen This points to a variable which will contain the number of bytes written to out.
 \param primitive This must point to the cryptographic primitive to be used.
 \param mode This must point to the cryptographic mode of operation to be used.
 \param key This should point to a buffer containing the encryption key.
 \param keySize This represents the length, in bytes, of the key buffer.
 \param iv This points to the initialization vector (this may be zero if the mode does not use an IV).
 \param cipherParams This points to specific cipher parameters, set to zero for default behavior.
 \param modeParams This points to specific mode of operation parameters, set to zero for default behavior.
 \return Returns \c ORDO_ESUCCESS on success, a negative error code on failure.
 \remark One downside of this function is that it is not possible to encrypt data in chunks - the whole plaintext must be available before encryption can begin.
 If your requirements make this unacceptable, you should use the encryption interface, located one level of abstraction lower - see encrypt.h.
 \remark The out buffer should have enough space to contain the entire ciphertext, which may be larger than the plaintext if a block mode with padding enabled
 is used. See remarks about padding in encrypt.h. */
int ordoEncrypt(unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen, BLOCK_CIPHER* primitive, BLOCK_CIPHER_MODE* mode, void* key, size_t keySize, void* iv, void* cipherParams, void* modeParams);

/*! This function decrypts a buffer of a given length with the provided parameters.
 \param in This points to a ciphertext buffer.
 \param inlen This contains the number of bytes of ciphertext.
 \param out This points to the buffer to which to write the plaintext.
 \param outlen This points to a variable which will contain the number of bytes written to out.
 \param primitive This must point to the cryptographic primitive to be used.
 \param mode This must point to the cryptographic mode of operation to be used.
 \param key This should point to a buffer containing the encryption key.
 \param keySize This represents the length, in bytes, of the key buffer.
 \param iv This points to the initialization vector (this may be zero if the mode does not use an IV).
 \param cipherParams This points to specific cipher parameters, set to zero for default behavior.
 \param modeParams This points to specific mode of operation parameters, set to zero for default behavior.
 \return Returns \c ORDO_ESUCCESS on success, a negative error code on failure.
 \remark Same remarks as for ordoEncrypt. */
int ordoDecrypt(unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen, BLOCK_CIPHER* primitive, BLOCK_CIPHER_MODE* mode, void* key, size_t keySize, void* iv, void* cipherParams, void* modeParams);

int ordoEncryptStream(unsigned char* in, size_t inlen, unsigned char* out, STREAM_CIPHER* primitive, void* key, size_t keySize, void* cipherParams);

int ordoDecryptStream(unsigned char* in, size_t inlen, unsigned char* out, STREAM_CIPHER* primitive, void* key, size_t keySize, void* cipherParams);

#endif
