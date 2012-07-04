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
}

/* This function returns an initialized cipher context with the provided parameters. */
CIPHER_CONTEXT* cipherInit(CIPHER_PRIMITIVE* primitive, CIPHER_MODE* mode, void* key, void* tweak, void* iv)
{
	/* Allocate memory for the context and populate it. */
	CIPHER_CONTEXT* ctx = salloc(sizeof(CIPHER_CONTEXT) * 50);
	ctx->primitive = primitive;
	ctx->mode = mode;

	/* Initialize the cipher context. */
	ctx->mode->fInit(ctx, key, tweak, iv);

	/* Return the context. */
	return ctx;
}

/* This function encrypts data using the passed cipher context. If decrypt is true, the cipher will decrypt instead. */
bool cipherUpdate(CIPHER_CONTEXT* ctx, unsigned char* buffer, size_t* size, bool final, bool decrypt)
{
	/* Encrypt or decrypt the buffer. */
	if (decrypt) ctx->mode->fDecrypt(ctx, buffer, size, final);
	else ctx->mode->fEncrypt(ctx, buffer, size, final);

	/* Return success. */
	return true;
}

/* This function finalizes a cipher context. */
bool cipherFinal(CIPHER_CONTEXT* ctx)
{
	/* Finalize the context. */
	ctx->mode->fFinal(ctx);

	/* Deallocate the context. */
	sfree(ctx, sizeof(CIPHER_CONTEXT));

	/* Return success. */
	return true;
}

/* This convenience function encrypts a buffer with a given key and IV. */
bool cipherEncrypt(unsigned char* buffer, size_t* size, CIPHER_PRIMITIVE* primitive, CIPHER_MODE* mode, void* key, void* tweak, void* iv)
{
	CIPHER_CONTEXT* ctx = cipherInit(primitive, mode, key, tweak, iv);
	if (ctx == 0) return false;
	if (!cipherUpdate(ctx, buffer, size, true, false)) return false;
	if (!cipherFinal(ctx)) return false;
	return true;
}

/* This convenience function decrypts a buffer with a given key and IV. */
bool cipherDecrypt(unsigned char* buffer, size_t* size, CIPHER_PRIMITIVE* primitive, CIPHER_MODE* mode, void* key, void* tweak, void* iv)
{
	CIPHER_CONTEXT* ctx = cipherInit(primitive, mode, key, tweak, iv);
	if (ctx == 0) return false;

	if (!cipherUpdate(ctx, buffer, size, true, true)) return false;
	if (!cipherFinal(ctx)) return false;
	return true;
}