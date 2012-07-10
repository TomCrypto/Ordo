/*! \file */

#include "encrypt.h"

/* Load Ordo. */
void loadOrdo();

/* Unload Ordo. */
void unloadOrdo();

/*! This convenience function encrypts a buffer of a given length with the provided parameters.
 \param buffer This points to a buffer to be encrypted.
 \param size This contains the size of the buffer to be encrypted.
 \param primitive This must point to the cryptographic primitive to be used
 \param mode This must point to the cryptographic mode of operation to be used
 \param key This must point to a buffer containing the raw key
 \param keySize This represents the length, in bytes, of the key buffer
 \param tweak This points to the tweak used in the cipher (this is an optional argument)
 \param iv This points to the initialization vector (this may be zero if the mode does not use an IV)
 \return Returns true on success, false on failure. 
 \remark If the selected mode is a block mode, padding is automatically applied and the buffer should have enough space to accomodate it. */
bool ordoEncrypt(unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen, CIPHER_PRIMITIVE* primitive, ENCRYPT_MODE* mode, void* key, size_t keySize, void* tweak, void* iv);

/*! This convenience function decrypts a buffer of a given length with the provided parameters.
 \param buffer This points to a buffer to be encrypted.
 \param size This contains the size of the buffer to be encrypted.
 \param primitive This must point to the cryptographic primitive to be used
 \param mode This must point to the cryptographic mode of operation to be used
 \param key This must point to a buffer containing the raw key
 \param keySize This represents the length, in bytes, of the key buffer
 \param tweak This points to the tweak used in the cipher (this is an optional argument)
 \param iv This points to the initialization vector (this may be zero if the mode does not use an IV)
 \return Returns true on success, false on failure. 
 \remark If the selected mode is a block mode, padding is automatically handled and padding data will be set to zero. */
bool ordoDecrypt(unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen, CIPHER_PRIMITIVE* primitive, ENCRYPT_MODE* mode, void* key, size_t keySize, void* tweak, void* iv);