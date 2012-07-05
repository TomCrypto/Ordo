/* Handles code related to symmetric ciphers (e.g. modes of operation). */
#include "encrypt.h"

/* Mode of operation list. */
#include "ecb.h"
#include "ctr.h"
#include "ofb.h"

/* Loads all cipher modes. */
void loadEncryptModes()
{
	ECB_SetMode(&ECB);
	CTR_SetMode(&CTR);
	OFB_SetMode(&OFB);
}

/* This function returns an initialized cipher context with the provided parameters. */
bool encryptInit(ENCRYPT_CONTEXT** ctx, CIPHER_PRIMITIVE* primitive, ENCRYPT_MODE* mode, void* key, size_t keySize, void* tweak, void* iv)
{
	/* Allocate memory for the context and populate it. */
	(*ctx) = salloc(sizeof(ENCRYPT_CONTEXT));
	(*ctx)->primitive = primitive;
	(*ctx)->mode = mode;

	/* Initialize the cipher context. */
	return (*ctx)->mode->fInit(*ctx, key, keySize, tweak, iv);
}

/* This function encrypts data using the passed cipher context. If decrypt is true, the cipher will decrypt instead. */
bool encryptUpdate(ENCRYPT_CONTEXT* ctx, unsigned char* buffer, size_t* size, bool final, bool decrypt)
{
	/* Encrypt or decrypt the buffer. */
	if (decrypt) return ctx->mode->fDecrypt(ctx, buffer, size, final);
	else return ctx->mode->fEncrypt(ctx, buffer, size, final);
}

/* This function finalizes a cipher context. */
void encryptFinal(ENCRYPT_CONTEXT* ctx)
{
	/* Finalize the context. */
	ctx->mode->fFinal(ctx);

	/* Deallocate the context. */
	sfree(ctx, sizeof(ENCRYPT_CONTEXT));
}