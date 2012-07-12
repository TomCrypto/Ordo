/* Handles code related to symmetric ciphers (e.g. modes of operation). */
#include "primitives.h"
#include "encrypt.h"
#include "encrypt.h"

/* Mode of operation list. */
#include "ecb.h"
#include "ctr.h"
#include "ofb.h"
#include "cfb.h"

/* Loads all cipher modes. */
void loadEncryptModes()
{
	ECB_SetMode(&ECB);
	CTR_SetMode(&CTR);
	OFB_SetMode(&OFB);
	CFB_SetMode(&CFB);
}

/* Unloads all cipher modes. */
void unloadEncryptModes()
{
	free(ECB);
	free(CTR);
	free(OFB);
	free(CFB);
}

/* This function returns an initialized encryption context using a specific primitive and mode of operation. */
ENCRYPT_CONTEXT* encryptCreate(CIPHER_PRIMITIVE* primitive, ENCRYPT_MODE* mode, bool direction, bool padding)
{
	ENCRYPT_CONTEXT* ctx = salloc(sizeof(ENCRYPT_CONTEXT));
	ctx->direction = direction;
	ctx->primitive = primitive;
	ctx->padding = padding;
	mode->fCreate(ctx);
	ctx->mode = mode;
	return ctx;
}

/* This function returns an initialized cipher context with the provided parameters. */
bool encryptInit(ENCRYPT_CONTEXT* ctx, void* key, size_t keySize, void* tweak, void* iv)
{
	/* Initialize the cipher context. */
	return ctx->mode->fInit(ctx, key, keySize, tweak, iv);
}

/* This function encrypts data using the passed cipher context. If decrypt is true, the cipher will decrypt instead. */
bool encryptUpdate(ENCRYPT_CONTEXT* ctx, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
{
	/* Encrypt or decrypt the buffer. */
	if (ctx->direction) return ctx->mode->fEncryptUpdate(ctx, in, inlen, out, outlen);
	else return ctx->mode->fDecryptUpdate(ctx, in, inlen, out, outlen);
}

/* This function finalizes a cipher context. */
bool encryptFinal(ENCRYPT_CONTEXT* ctx, unsigned char* out, size_t* outlen)
{
	/* Finalize the context. */
	if (ctx->direction) return ctx->mode->fEncryptFinal(ctx, out, outlen);
	else return ctx->mode->fDecryptFinal(ctx, out, outlen);
}

/* This function frees an initialized encryption context. */
void encryptFree(ENCRYPT_CONTEXT* ctx)
{
	ctx->mode->fFree(ctx);
	sfree(ctx, sizeof(ENCRYPT_CONTEXT));
}