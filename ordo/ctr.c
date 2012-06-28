/* CTR mode of operation. */

#include "cipher.h"
#include "ctr.h"

/* Increments an IV of variable size. */
void incIV(char* iv, size_t len)
{
	/* Go over each byte and carry over addition. */
	char* p = iv;
	size_t t;
	size_t carry;
	*p++;
	carry = (*p == 0);
	p++;

	for (t = 1; t < len; t++)
	{
		if (carry) (*(p + t))++;
		carry = (*(p + t) == 0);
	}
}

/* Initializes a CTR context (the primitive and mode must have been filled in). */
void CTR_Init(CIPHER_CONTEXT* ctx, void* key, void* tweak, void* iv)
{
	/* Allocate memory for the key, iv and block. */
	ctx->key = salloc(ctx->primitive->szKey);
	ctx->block = salloc(ctx->primitive->szBlock);
	ctx->iv = salloc(ctx->primitive->szBlock);
	ctx->blockSize = 0;

	/* Copy the IV (required) into the context IV. */
	memcpy(ctx->iv, iv, ctx->primitive->szBlock); 

	/* Perform the key schedule. */
	ctx->primitive->fKeySchedule(key, tweak, ctx->key);
}

/* Encrypts a buffer of data in CTR mode. The padding flag is irrelevant. */
void CTR_Encrypt(CIPHER_CONTEXT* ctx, char* buffer, size_t* size, size_t padding)
{
	/* Save the current size. */
	size_t sz = *size;

	/* Go over the buffer byte per byte. */
	while (sz != 0)
	{
		/* If there is no data left in the context block, update. */
		if (ctx->blockSize == 0)
		{
			/* CTR update (increment IV, copy IV size_to block, encrypt block) */
			incIV((char*)ctx->iv, ctx->primitive->szBlock);
			memcpy(ctx->block, ctx->iv, ctx->primitive->szBlock);
			ctx->primitive->fPermutation(ctx->block, ctx->key);
			ctx->blockSize = ctx->primitive->szBlock;
		}

		/* Encrypt this plasize_text byte. */
		*buffer ^= *((char*)(ctx->block) + ctx->primitive->szBlock - ctx->blockSize);

		ctx->blockSize--;
		buffer++;
		sz--;
	}
}

/* Decrypts a buffer of data in CTR mode. The padding flag is irrelevant. */
void CTR_Decrypt(CIPHER_CONTEXT* ctx, char* buffer, size_t* size, size_t padding)
{
	/* CTR encryption and decryption are equivalent. */
	CTR_Encrypt(ctx, buffer, size, padding);
}

/* Finalizes a CTR context. */
void CTR_Final(CIPHER_CONTEXT* ctx)
{
	// IMPLEMENT SECURE FREE HERE !!!
	/* Free used resources. */
	sfree(ctx->key, ctx->primitive->szKey);
	sfree(ctx->block, ctx->primitive->szBlock);
	sfree(ctx->iv, ctx->primitive->szBlock);
}

/* Fills a CIPHER_MODE struct with the correct information. */
void CTR_SetMode(CIPHER_MODE* mode)
{
	mode->fInit = &CTR_Init;
	mode->fEncrypt = &CTR_Encrypt;
	mode->fDecrypt = &CTR_Decrypt;
	mode->fFinal = &CTR_Final;
	mode->name = (char*)malloc(sizeof("CTR"));
	strcpy_s(mode->name, sizeof("CTR"), "CTR");
}