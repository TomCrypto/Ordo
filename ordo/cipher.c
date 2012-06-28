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

/* This function encrypts a buffer with a given key and IV. */
size_t cipherEncrypt(char* buffer, size_t* size, CIPHER_PRIMITIVE primitive, CIPHER_MODE mode, void* key, void* tweak, void* iv)
{
	/* Create a context and set primitive/mode. */
	CIPHER_CONTEXT* ctx = salloc(sizeof(CIPHER_CONTEXT));
	ctx->primitive = &primitive;
	ctx->mode = &mode;

	/* Initialize the context. */
	ctx->mode->fInit(ctx, key, tweak, iv);

	/* Decrypt. */
	ctx->mode->fEncrypt(ctx, buffer, size, 1);

	/* Finalize the context. */
	ctx->mode->fFinal(ctx);

	/* Deallocate the context. */
	sfree(ctx, sizeof(CIPHER_CONTEXT));

	/* Return success. */
	return 1;
}

// INSECURE
/* This function decrypts a buffer with a given key and IV. */
size_t cipherDecrypt(char* buffer, size_t* size, CIPHER_PRIMITIVE primitive, CIPHER_MODE mode, void* key, void* tweak, void* iv)
{
	/* Create a context and set primitive/mode. */
	CIPHER_CONTEXT* ctx = salloc(sizeof(CIPHER_CONTEXT));
	ctx->primitive = &primitive;
	ctx->mode = &mode;

	/* Initialize the context. */
	ctx->mode->fInit(ctx, key, tweak, iv);

	/* Decrypt. */
	ctx->mode->fDecrypt(ctx, buffer, size, 1);

	/* Finalize the context. */
	ctx->mode->fFinal(ctx);

	/* Deallocate the context. */
	sfree(ctx, sizeof(CIPHER_CONTEXT));

	/* Return success. */
	return 1;
}