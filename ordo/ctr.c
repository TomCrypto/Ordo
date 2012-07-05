/* CTR mode of operation. */

#include "encrypt.h"
#include "ctr.h"

/* Increments an IV of arbitrary size as if it were a len-byte integer
   Propagation is done from left-to-right in memory storage order. */
void incIV(unsigned char* iv, size_t len)
{
	/* Increment the first byte. */
	size_t t;
	bool carry = (++*iv == 0);

	/* Go over each byte, and propagate the carry. */
	for (t = 1; t < len; t++)
	{
		if (carry) carry = (++*(iv + t) == 0);
		else break;
	}
}

/* Initializes a CTR context (the primitive and mode must have been filled in). */
bool CTR_Init(ENCRYPT_CONTEXT* ctx, void* key, size_t keySize, void* tweak, void* iv)
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

/* Encrypts a buffer of data in CTR mode. The "final" flag is irrelevant. */
bool CTR_Encrypt(ENCRYPT_CONTEXT* ctx, unsigned char* buffer, size_t* size, bool final)
{
	/* Save the buffer size as it will not be changed. */
	size_t sz = *size;

	/* Go over the buffer byte per byte. */
	while (sz != 0)
	{
		/* If there is no data left in the context block, update. */
		if (ctx->blockSize == 0)
		{
			/* CTR update (increment IV, copy IV size_to block, encrypt block). */
			incIV((unsigned char*)ctx->iv, ctx->primitive->szBlock);
			memcpy(ctx->block, ctx->iv, ctx->primitive->szBlock);
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

/* Decrypts a buffer of data in CTR mode. The "final" flag is irrelevant. */
bool CTR_Decrypt(ENCRYPT_CONTEXT* ctx, unsigned char* buffer, size_t* size, bool final)
{
	/* CTR encryption and decryption are equivalent. */
	return CTR_Encrypt(ctx, buffer, size, final);
}

/* Finalizes a CTR context. */
void CTR_Final(ENCRYPT_CONTEXT* ctx)
{
	/* Free used resources. */
	sfree(ctx->key, ctx->primitive->szKey);
	sfree(ctx->block, ctx->primitive->szBlock);
	sfree(ctx->iv, ctx->primitive->szBlock);
}

/* Fills a ENCRYPT_MODE struct with the correct information. */
void CTR_SetMode(ENCRYPT_MODE** mode)
{
	(*mode) = salloc(sizeof(ENCRYPT_MODE));
	(*mode)->fInit = &CTR_Init;
	(*mode)->fEncrypt = &CTR_Encrypt;
	(*mode)->fDecrypt = &CTR_Decrypt;
	(*mode)->fFinal = &CTR_Final;
	(*mode)->name = "CTR";
}