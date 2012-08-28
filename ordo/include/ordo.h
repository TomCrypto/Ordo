#ifndef ordo_h
#define ordo_h

/*! \file */

#include <common/ordotypes.h>
#include <encrypt/encrypt.h>
#include <random/random.h>

/* Load Ordo. */
void loadOrdo();

/* Unload Ordo. */
void unloadOrdo();

/*! This convenience function encrypts a buffer of a given length with the provided parameters.
 \param in This points to a buffer of plaintext.
 \param inlen This contains the number of bytes of plaintext.
 \param out This points to the buffer in which to write the ciphertext.
 \param outlen This points to an integer containing the number of bytes of ciphertext produced.
 \param primitive This must point to the cryptographic primitive to be used.
 \param mode This must point to the cryptographic mode of operation to be used.
 \param key This must point to a buffer containing the raw key.
 \param keySize This represents the length, in bytes, of the key buffer.
 \param tweak This points to the tweak used in the cipher (this is an optional argument).
 \param iv This points to the initialization vector (this may be zero if the mode does not use an IV).
 \return Returns 0 on success, a negative error code on failure. */
int ordoEncrypt(unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen, CIPHER_PRIMITIVE* primitive, ENCRYPT_MODE* mode, void* key, size_t keySize, void* iv);

/*! This convenience function decrypts a buffer of a given length with the provided parameters.
 \param in This points to a buffer of ciphertext.
 \param inlen This contains the number of bytes of ciphertext.
 \param out This points to the buffer in which to write the plaintext.
 \param outlen This points to an integer containing the number of bytes of plaintext produced.
 \param primitive This must point to the cryptographic primitive to be used.
 \param mode This must point to the cryptographic mode of operation to be used.
 \param key This must point to a buffer containing the raw key.
 \param keySize This represents the length, in bytes, of the key buffer.
 \param tweak This points to the tweak used in the cipher (this is an optional argument).
 \param iv This points to the initialization vector (this may be zero if the mode does not use an IV).
 \return Returns 0 on success, a negative error code on failure. */
int ordoDecrypt(unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen, CIPHER_PRIMITIVE* primitive, ENCRYPT_MODE* mode, void* key, size_t keySize, void* iv);

#endif
