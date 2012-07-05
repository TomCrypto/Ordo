#include "ordo.h"

/* Initialize Ordo. */
void ordoInit()
{
	loadPrimitives();
	loadEncryptModes();
}

/* This convenience function encrypts or decrypts a buffer with a given key, tweak and IV. */
bool ordoEncrypt(unsigned char* buffer, size_t* size, CIPHER_PRIMITIVE* primitive, ENCRYPT_MODE* mode, void* key, size_t keySize, void* tweak, void* iv)
{
	ENCRYPT_CONTEXT* ctx;
	if (!encryptInit(&ctx, primitive, mode, key, keySize, tweak, iv)) return false;
	if (!encryptUpdate(ctx, buffer, size, true, false)) return false;
	encryptFinal(ctx);
	return true;
}

/* This convenience function decrypts a buffer with a given key, tweak and IV. */
bool ordoDecrypt(unsigned char* buffer, size_t* size, CIPHER_PRIMITIVE* primitive, ENCRYPT_MODE* mode, void* key, size_t keySize, void* tweak, void* iv)
{
	ENCRYPT_CONTEXT* ctx;
	if (!encryptInit(&ctx, primitive, mode, key, keySize, tweak, iv)) return false;
	if (!encryptUpdate(ctx, buffer, size, true, true)) return false;
	encryptFinal(ctx);
	return true;
}