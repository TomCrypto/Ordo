/* Handles code related to symmetric ciphers (e.g. modes of operation). */
#include "cipher.h"

/* Loads all cipher primitives. */
void loadPrimitives()
{
	Identity_SetPrimitive(&IDENTITY);
	XORToy_SetPrimitive(&XORTOY);
	Threefish_SetPrimitive(&THREEFISH);
}

/* Loads all cipher modes. */
void loadModes()
{
	ECB_SetMode(&ECB);
	CTR_SetMode(&CTR);
	OFB_SetMode(&OFB);
}

/* This function returns an initialized cipher context with the provided parameters. */
bool cipherInit(CIPHER_CONTEXT** ctx, CIPHER_PRIMITIVE* primitive, CIPHER_MODE* mode, void* key, size_t keySize, void* tweak, void* iv)
{
	/* Allocate memory for the context and populate it. */
	(*ctx) = salloc(sizeof(CIPHER_CONTEXT));
	(*ctx)->primitive = primitive;
	(*ctx)->mode = mode;

	/* Initialize the cipher context. */
	return (*ctx)->mode->fInit(*ctx, key, keySize, tweak, iv);
}

/* This function encrypts data using the passed cipher context. If decrypt is true, the cipher will decrypt instead. */
bool cipherUpdate(CIPHER_CONTEXT* ctx, unsigned char* buffer, size_t* size, bool final, bool decrypt)
{
	/* Encrypt or decrypt the buffer. */
	if (decrypt) return ctx->mode->fDecrypt(ctx, buffer, size, final);
	else return ctx->mode->fEncrypt(ctx, buffer, size, final);
}

/* This function finalizes a cipher context. */
void cipherFinal(CIPHER_CONTEXT* ctx)
{
	/* Finalize the context. */
	ctx->mode->fFinal(ctx);

	/* Deallocate the context. */
	sfree(ctx, sizeof(CIPHER_CONTEXT));
}

/* This convenience function encrypts a buffer with a given key, tweak and IV. */
bool cipherEncrypt(unsigned char* buffer, size_t* size, CIPHER_PRIMITIVE* primitive, CIPHER_MODE* mode, void* key, size_t keySize, void* tweak, void* iv)
{
	CIPHER_CONTEXT* ctx;
	if (!cipherInit(&ctx, primitive, mode, key, keySize, tweak, iv)) return false;
	if (!cipherUpdate(ctx, buffer, size, true, false)) return false;
	cipherFinal(ctx);
	return true;
}

/* This convenience function decrypts a buffer with a given key, tweak and IV. */
bool cipherDecrypt(unsigned char* buffer, size_t* size, CIPHER_PRIMITIVE* primitive, CIPHER_MODE* mode, void* key, size_t keySize, void* tweak, void* iv)
{
	CIPHER_CONTEXT* ctx;
	if (!cipherInit(&ctx, primitive, mode, key, keySize, tweak, iv)) return false;
	if (!cipherUpdate(ctx, buffer, size, true, true)) return false;
	cipherFinal(ctx);
	return true;
}