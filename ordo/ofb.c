/* OFB mode of operation. */

#include "encrypt.h"
#include "ofb.h"

/* Initializes an OFB context (the primitive and mode must have been filled in). */
bool OFB_Init(ENCRYPT_CONTEXT* ctx, void* key, size_t keySize, void* tweak, void* iv)
{
	/* Check the key size. */
	if (!ctx->primitive->fKeySizeCheck(keySize)) return false;

	/* Allocate memory for the key, iv and block. */
	ctx->key = salloc(ctx->primitive->szKey);
	ctx->block = salloc(ctx->primitive->szBlock);
	ctx->iv = salloc(ctx->primitive->szBlock);

	/* Copy the IV (required) into the context IV. */
	memcpy(ctx->iv, iv, ctx->primitive->szBlock); 

	/* Perform the key schedule. */
	if (!ctx->primitive->fKeySchedule(key, keySize, tweak, ctx->key)) return false;

	/* Compute the initial keystream block. */
	memcpy(ctx->block, ctx->iv, ctx->primitive->szBlock);
	ctx->primitive->fPermutation(ctx->block, ctx->key);
	ctx->blockSize = ctx->primitive->szBlock;

	/* Return success. */
	return true;
}

/* Encrypts a buffer of data in OFB mode. The "final" flag is irrelevant. */
bool OFB_Encrypt(ENCRYPT_CONTEXT* ctx, unsigned char* buffer, size_t* size, bool final)
{
	/* Save the buffer size as it will not be changed. */
	size_t sz = *size;

	/* Go over the buffer byte per byte. */
	while (sz != 0)
	{
		/* If there is no data left in the context block, update. */
		if (ctx->blockSize == 0)
		{
			/* OFB update (simply apply the permutation function again). */
			ctx->primitive->fPermutation(ctx->block, ctx->key);
			ctx->blockSize = ctx->primitive->szBlock;
		}

		/* Encrypt this plainext byte. */
		*buffer ^= *((unsigned char*)(ctx->block) + ctx->primitive->szBlock - ctx->blockSize);

		ctx->blockSize--;
		buffer++;
		sz--;
	}

	/* Return success. */
	return true;
}

/* Decrypts a buffer of data in OFB mode. The "final" flag is irrelevant. */
bool OFB_Decrypt(ENCRYPT_CONTEXT* ctx, unsigned char* buffer, size_t* size, bool final)
{
	/* OFB encryption and decryption are equivalent. */
	return OFB_Encrypt(ctx, buffer, size, final);
}

/* Finalizes an OFB context. */
void OFB_Final(ENCRYPT_CONTEXT* ctx)
{
	/* Free used resources. */
	sfree(ctx->key, ctx->primitive->szKey);
	sfree(ctx->block, ctx->primitive->szBlock);
	sfree(ctx->iv, ctx->primitive->szBlock);
}

/* Fills a ENCRYPT_MODE struct with the correct information. */
void OFB_SetMode(ENCRYPT_MODE** mode)
{
	(*mode) = salloc(sizeof(ENCRYPT_MODE));
	(*mode)->fInit = &OFB_Init;
	(*mode)->fEncrypt = &OFB_Encrypt;
	(*mode)->fDecrypt = &OFB_Decrypt;
	(*mode)->fFinal = &OFB_Final;
	(*mode)->name = "OFB";
}