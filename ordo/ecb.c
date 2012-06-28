/* ECB mode of operation. */

#include "cipher.h"
#include "ecb.h"

/* Initializes an ECB context (the primitive and mode must have been filled in). */
void ECB_Init(CIPHER_CONTEXT* ctx, void* key, void* tweak, void* iv)
{
	/* Allocate memory for the key and block. */
	ctx->key = salloc(ctx->primitive->szKey);
	ctx->block = salloc(ctx->primitive->szBlock);
	ctx->blockSize = 0;

	/* Perform the key schedule. */
	ctx->primitive->fKeySchedule(key, tweak, ctx->key);
}

/* Encrypts a buffer in ECB mode. It is assumed the buffer has one extra block. */
void ECB_Encrypt(CIPHER_CONTEXT* ctx, char* buffer, size_t* size, size_t padding)
{
	/* Save the buffer size. */
	size_t sz = *size;

	/* Encrypt all size_tegral blocks except the last one, using the context. */
	while (*size + ctx->primitive->szBlock > padding - 1 + ctx->primitive->szBlock)
	{
		/* Encrypt this block. */
		ctx->primitive->fPermutation(buffer, ctx->key);

		/* Go to the next block. */
		*size -= ctx->primitive->szBlock;
		buffer += ctx->primitive->szBlock;
	}

	/* If we want padding. */
	if (padding == 1)
	{
		/* Set the final buffer block to contain the buffer's size. */
		memset(buffer, 0, ctx->primitive->szBlock);
		memcpy(buffer, &sz, sizeof(sz));

		/* Encrypt the final block. */
		ctx->primitive->fPermutation(buffer, ctx->key);

		/* Return the padded buffer size. */
		*size = sz + ctx->primitive->szBlock + (ctx->primitive->szBlock - sz % ctx->primitive->szBlock) % ctx->primitive->szBlock; // wtf
	}
	else
	{
		/* Otherwise just return the original size. */
		*size = sz;
	}
}

/* Decrypts a buffer in ECB mode. It is assumed the buffer has enough space for padding. */
void ECB_Decrypt(CIPHER_CONTEXT* ctx, char* buffer, size_t* size, size_t padding)
{
	/* Save the buffer size. */
	size_t sz = *size;

	/* Decrypt all size_tegral blocks using the context. */
	while (*size + ctx->primitive->szBlock > padding - 1 + ctx->primitive->szBlock)
	{
		/* Decrypt this block. */
		ctx->primitive->fInverse(buffer, ctx->key);

		/* Go to the next block. */
		*size -= ctx->primitive->szBlock;
		buffer += ctx->primitive->szBlock;
	}

	if (padding == 1)
	{
		/* Read the amount of padding used for this buffer. */
		memcpy(size, buffer - ctx->primitive->szBlock, sizeof(*size));

		/* Clear the final block. */
		memset(buffer - ctx->primitive->szBlock, 0, ctx->primitive->szBlock);
	}
	else
	{
		/* Return the original size. */
		*size = sz;
	}
}

/* Finalizes an ECB context. */
void ECB_Final(CIPHER_CONTEXT* ctx)
{
	// IMPLEMENT SECURE FREE HERE !!!
	/* Free used resources. */
	sfree(ctx->key, ctx->primitive->szKey);
	sfree(ctx->block, ctx->primitive->szBlock);
}

/* Fills a CIPHER_MODE struct with the correct information. */
void ECB_SetMode(CIPHER_MODE* mode)
{
	mode->fInit = &ECB_Init;
	mode->fEncrypt = &ECB_Encrypt;
	mode->fDecrypt = &ECB_Decrypt;
	mode->fFinal = &ECB_Final;
	mode->name = (char*)malloc(sizeof("ECB"));
	strcpy_s(mode->name, sizeof("ECB"), "ECB");
}