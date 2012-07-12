#include "primitives.h"
#include "encrypt.h"
#include "ordo.h"

/* Load Ordo. */
void loadOrdo()
{
	/* Load all cryptographic primitives. */
	loadPrimitives();

	/* Load all encryption modes of operation. */
	loadEncryptModes();
}

/* Unload Ordo. */
void unloadOrdo()
{
	/* Unload all encryption modes of operation. */
	unloadEncryptModes();

	/* Unload all cryptographic primitives. */
	unloadPrimitives();
}

/* This convenience function encrypts or decrypts a buffer with a given key, tweak and IV. */
bool ordoEncrypt(unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen, CIPHER_PRIMITIVE* primitive, ENCRYPT_MODE* mode, void* key, size_t keySize, void* tweak, void* iv, bool padding)
{
	size_t total = 0;
	ENCRYPT_CONTEXT* ctx = encryptCreate(primitive, mode, true, padding);
	if (!encryptInit(ctx, key, keySize, tweak, iv)) return false;
	if (!encryptUpdate(ctx, in, inlen, out, outlen)) return false;
	total += *outlen;
	if (!encryptFinal(ctx, out + *outlen, outlen)) return false;
	total += *outlen;
	encryptFree(ctx);
	*outlen = total;
	return true;

	/* size_t t;
	size_t total = 0;
	ENCRYPT_CONTEXT* ctx = encryptCreate(primitive, mode, true, padding);
	if (!encryptInit(ctx, key, keySize, tweak, iv)) return false;

	for (t = 0; t < inlen; t++)
	{
		if (!encryptUpdate(ctx, in, 1, out + total, outlen)) return false;
		total += *outlen;
		in++;
	}

	if (!encryptFinal(ctx, out + total, outlen)) return false;
	total += *outlen;
	encryptFree(ctx);
	*outlen = total;
	return true; */
}

/* This convenience function decrypts a buffer with a given key, tweak and IV. */
bool ordoDecrypt(unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen, CIPHER_PRIMITIVE* primitive, ENCRYPT_MODE* mode, void* key, size_t keySize, void* tweak, void* iv, bool padding)
{
	size_t total = 0;
	ENCRYPT_CONTEXT* ctx = encryptCreate(primitive, mode, false, padding);
	if (!encryptInit(ctx, key, keySize, tweak, iv)) return false;
	if (!encryptUpdate(ctx, in, inlen, out, outlen)) return false;
	total += *outlen;
	if (!encryptFinal(ctx, out + total, outlen)) return false;
	total += *outlen;
	encryptFree(ctx);
	*outlen = total;
	return true;

	/* size_t t;
	size_t total = 0;
	ENCRYPT_CONTEXT* ctx = encryptCreate(primitive, mode, false, padding);
	if (!encryptInit(ctx, key, keySize, tweak, iv)) return false;

	for (t = 0; t < inlen; t++)
	{
		if (!encryptUpdate(ctx, in, 1, out + total, outlen)) return false;
		total += *outlen;
		in++;
	}

	if (!encryptFinal(ctx, out + total, outlen)) return false;
	total += *outlen;
	encryptFree(ctx);
	*outlen = total;
	return true; */
}