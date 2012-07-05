/* ECB mode of operation. */

#include "encrypt.h"
#include "ecb.h"

/* Checks whether the next padding bytes at buffer all have the correct padding value. */
bool padcheck(unsigned char* buffer, size_t padding)
{
	/* Iterate over all padding bytes at the end of the block. */
	size_t t;
	for (t = 0; t < padding; t++)
		if ((size_t)*(buffer + t) != padding)
			return false;

	/* All bytes are valid, the padding is acceptable. */
	return true;
}

/* Initializes an ECB context (the primitive and mode must have been filled in). */
bool ECB_Init(ENCRYPT_CONTEXT* ctx, void* key, size_t keySize, void* tweak, void* iv)
{
	/* Check the key size. */
	if (!ctx->primitive->fKeySizeCheck(keySize)) return false;

	/* Allocate memory for the key and block. */
	ctx->key = salloc(ctx->primitive->szKey);
	ctx->block = salloc(ctx->primitive->szBlock);
	ctx->blockSize = 0;

	/* Perform the key schedule. */
	return ctx->primitive->fKeySchedule(key, keySize, tweak, ctx->key);
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
bool ECB_Encrypt(ENCRYPT_CONTEXT* ctx, unsigned char* buffer, size_t* size, bool final)
{
	/* Save the buffer size. */
	size_t sz = *size;

	/* If padding is disabled, check the buffer size. */
	if (!final) assert(sz % ctx->primitive->szBlock == 0);

	/* If padding is enabled, ignore the last block for now (which will be used for padding). */
	if (final) sz -= sz % ctx->primitive->szBlock;

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

	/* Return success. */
	return true;
}

/* Decrypts a buffer in ECB mode. It is assumed the buffer has enough space for padding. */
bool ECB_Decrypt(ENCRYPT_CONTEXT* ctx, unsigned char* buffer, size_t* size, bool final)
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

		/* Read the amount of padding appended to the buffer. */
		padding = (size_t)*(buffer + ctx->primitive->szBlock - 1);

		/* Perform padding check to verify decryption (this is not a guarantee but rather a failsafe). */
		if (!padcheck(buffer + ctx->primitive->szBlock - padding, padding))
		{
			/* If the padding fails (could be corrupted ciphertext or invalid key) return a decryption size 0. */
			*size = 0;
			return false;
		}

		/* Set the appended padding to zero. */
		memset(buffer + ctx->primitive->szBlock - padding, 0, padding);

		/* Return the correct buffer size. */
		*size -= padding;
	}

	/* Return success. */
	return true;
}

/* Finalizes an ECB context. */
void ECB_Final(ENCRYPT_CONTEXT* ctx)
{
	/* Free used resources. */
	sfree(ctx->key, ctx->primitive->szKey);
	sfree(ctx->block, ctx->primitive->szBlock);
}

/* Fills a ENCRYPT_MODE struct with the correct information. */
void ECB_SetMode(ENCRYPT_MODE** mode)
{
	(*mode) = salloc(sizeof(ENCRYPT_MODE));
	(*mode)->fInit = &ECB_Init;
	(*mode)->fEncrypt = &ECB_Encrypt;
	(*mode)->fDecrypt = &ECB_Decrypt;
	(*mode)->fFinal = &ECB_Final;
	(*mode)->name = "ECB";
}