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

/* Encrypts a buffer in ECB mode. The buffer must be a multiple of the block
   cipher's size. If "final" is true, padding will be applied to the final
   block, otherwise there will be no padding. If "final" is true, it is
   assumed the last block of the buffer has at least 1 byte reserved for
   padding.
   
   If final == false, then size should be a multiple of the cipher's block
   size and buffer should contain this number of bytes. The resulting size
   will remain the same.
   
   If final == true, then size should be the size of the actual data in
   the buffer (the extra space allocated to the buffer for padding should
   not be included in size), and the resulting size will contain the space
   of the buffer including the padding. */
void ECB_Encrypt(CIPHER_CONTEXT* ctx, unsigned char* buffer, size_t* size, bool final)
{
	/* Save the buffer size. */
	size_t sz = *size;

	/* If padding is disabled, check the buffer size. */
	if (!final) assert(sz % ctx->primitive->szBlock == 0);

	/* If padding is enabled, ignore the last block for now (which will be used for padding). */
	if (final)
	{
		if (sz % ctx->primitive->szBlock == 0) sz -= ctx->primitive->szBlock;
		else sz -= sz % ctx->primitive->szBlock;
	}

	/* Encrypt all integral blocks (except the last one if padding is enabled). */
	while (sz != 0)
	{
		/* Encrypt this block. */
		ctx->primitive->fPermutation(buffer, ctx->key);

		/* Go to the next block. */
		sz -= ctx->primitive->szBlock;
		buffer += ctx->primitive->szBlock;
	}

	/* At this point, if no padding is required, we are done, otherwise we need to pad. */
	if (final)
	{
		/* Find the amount of padding required (between 1 and the block size). */
		size_t padding = (ctx->primitive->szBlock - *size % ctx->primitive->szBlock);
		if (padding == 0) padding = ctx->primitive->szBlock;

		/* Pad the buffer accordingly. */
		memset(buffer + *size % ctx->primitive->szBlock, padding, padding);

		/* Encrypt this final block. */
		ctx->primitive->fPermutation(buffer, ctx->key);

		/* Return the amount of data encrypted. */
		if (*size % ctx->primitive->szBlock == 0) *size += ctx->primitive->szBlock;
		else *size += ctx->primitive->szBlock - *size % ctx->primitive->szBlock;
	}
}

/* Decrypts a buffer in ECB mode. It is assumed the buffer has enough space for padding. */
void ECB_Decrypt(CIPHER_CONTEXT* ctx, unsigned char* buffer, size_t* size, bool final)
{
	/* Save the buffer size. */
	size_t sz = *size;
	size_t padding;

	/* Check the buffer size. */
	assert(sz % ctx->primitive->szBlock == 0);

	/* If padding is enabled, ignore the last block for now (which will be used for padding). */
	if (final) sz -= ctx->primitive->szBlock;

	/* Decrypt all integral blocks (except the last one if padding is enabled). */
	while (sz != 0)
	{
		/* Decrypt this block. */
		ctx->primitive->fInverse(buffer, ctx->key);

		/* Go to the next block. */
		sz -= ctx->primitive->szBlock;
		buffer += ctx->primitive->szBlock;
	}

	/* At this point, if this isn't a final buffer, we are done, otherwise we need to handle the padding. */
	if (final)
	{
		/* Decrypt this final block. */
		ctx->primitive->fInverse(buffer, ctx->key);

		// PERFORM CHECK HERE

		/* Read the amount of padding appended to the buffer. */
		padding = (size_t)*(buffer + ctx->primitive->szBlock - 1);

		/* Set the appended padding to zero. */
		memset(buffer + ctx->primitive->szBlock - padding, 0, padding);

		/* Return the correct buffer size. */
		*size -= padding;
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
void ECB_SetMode(CIPHER_MODE** mode)
{
	(*mode) = salloc(sizeof(CIPHER_MODE));
	(*mode)->fInit = &ECB_Init;
	(*mode)->fEncrypt = &ECB_Encrypt;
	(*mode)->fDecrypt = &ECB_Decrypt;
	(*mode)->fFinal = &ECB_Final;
	(*mode)->name = (char*)malloc(sizeof("ECB"));
	strcpy_s((*mode)->name, sizeof("ECB"), "ECB");
}