/*! \file */

/* ECB mode of operation. */

#include "encrypt.h"
#include "ecb.h"

/*! This is extra context space required by the ECB mode to store temporary incomplete data buffers.*/
typedef struct RESERVED
{
	/*! The temporary block, the size of the primitive's block size. */
	unsigned char* block;
	/*! The amount of bytes of plaintext or ciphertext currently in the temporary block. */
	size_t available;
} RESERVED;

/*! This structure describes a symmetric encryption context for the ECB mode. */
typedef struct ECB_ENCRYPT_CONTEXT
{
	/*! The primitive to use. */
	CIPHER_PRIMITIVE* primitive;
	/*! The mode of operation to use (this is set to the ECB mode). */
	struct ENCRYPT_MODE* mode;
	/*! Points to the key material. */
	void* key;
	/*! Unused field (ECB uses no initialization vector). */
	void* iv;
	/*! Reserved space for the ECB mode of operation. */
	RESERVED* reserved;
} ECB_ENCRYPT_CONTEXT;

/* Checks whether the next padding bytes at buffer all have the correct padding value. */
bool padcheck(unsigned char* buffer, unsigned char padding)
{
	/* Iterate over all padding bytes at the end of the block. */
	size_t t;
	for (t = 0; t < padding; t++)
		if ((unsigned char)*(buffer + t) != padding)
			return false;

	/* All bytes are valid, the padding is acceptable. */
	return true;
}

void ECB_Create(ECB_ENCRYPT_CONTEXT* ctx)
{
	/* Allocate context fields. */
	ctx->key = salloc(ctx->primitive->szKey);
	ctx->reserved = salloc(sizeof(RESERVED));
	ctx->reserved->block = salloc(ctx->primitive->szBlock);
	ctx->reserved->available = 0;
}

/*! Initializes an ECB context (the primitive and mode must have been filled in).
  \param ctx The initialized encryption context.
  \param key A pointer to the key to use for encryption.
  \param keySize The size, in bytes, of the key.
  \param tweak The tweak to use (this may be zero, depending on the primitive).
  \param iv Set this to zero, as the ECB mode uses no initialization vector.
  \return Returns true on success, false on failure. */
bool ECB_Init(ECB_ENCRYPT_CONTEXT* ctx, void* key, size_t keySize, void* tweak, void* iv)
{
	/* Check the key size. */
	if (!ctx->primitive->fKeySizeCheck(keySize)) return false;

	/* Perform the key schedule. */
	return ctx->primitive->fKeySchedule(key, keySize, tweak, ctx->key);
}

/*! Encrypts a buffer in ECB mode. The context must have been allocated and initialized.
  \param ctx The initialized encryption context.
  \param in A pointer to the plaintext buffer.
  \param inlen The size of the plaintext buffer, in bytes.
  \param out A pointer to the ciphertext buffer.
  \param outlen A pointer to an integer which will contain the amount of ciphertext output, in bytes.
  \return Returns true on success, false on failure.
  \remark The out buffer must have enough space to accomodate up to one more block size of ciphertext than plaintext, rounded down to the nearest block. */
bool ECB_EncryptUpdate(ECB_ENCRYPT_CONTEXT* ctx, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
{
	/* Initialize output size. */
	*outlen = 0;

	/* Process all full blocks. */
	while (ctx->reserved->available + inlen >= ctx->primitive->szBlock)
	{
		/* Copy it in, and process it. */
		memcpy(ctx->reserved->block + ctx->reserved->available, in, ctx->primitive->szBlock - ctx->reserved->available);

		/* Encrypt the block. */
		ctx->primitive->fPermutation(ctx->reserved->block, ctx->key);

		/* Write back the block to the output. */
		memcpy(out, ctx->reserved->block, ctx->primitive->szBlock);
		*outlen += ctx->primitive->szBlock;
		out += ctx->primitive->szBlock;

		/* Go forward in the input buffer. */
		inlen -= ctx->primitive->szBlock - ctx->reserved->available;
		in += ctx->primitive->szBlock - ctx->reserved->available;
		ctx->reserved->available = 0;
	}

	/* Add whatever is left in the temporary buffer. */
	memcpy(ctx->reserved->block + ctx->reserved->available, in, inlen);
	ctx->reserved->available += inlen;

	/* We're done. */
	return true;
}

/*! Decrypts a buffer in ECB mode. The context must have been allocated and initialized.
  \param ctx The initialized encryption context.
  \param in A pointer to the ciphertext buffer.
  \param inlen The size of the ciphertext buffer, in bytes.
  \param out A pointer to the plaintext buffer.
  \param outlen A pointer to an integer which will contain the amount of plaintext output, in bytes.
  \return Returns true on success, false on failure.
  \remark The out buffer must have enough space to accomodate up to one more block size of plaintext than ciphertext, rounded down to the nearest block. */
bool ECB_DecryptUpdate(ECB_ENCRYPT_CONTEXT* ctx, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
{
	/* Initialize output size. */
	*outlen = 0;

	/* Process all full blocks except the last potential block. */
	while (ctx->reserved->available + inlen > ctx->primitive->szBlock)
	{
		/* Copy it in, and process it. */
		memcpy(ctx->reserved->block + ctx->reserved->available, in, ctx->primitive->szBlock - ctx->reserved->available);

		/* Decrypt the block. */
		ctx->primitive->fInverse(ctx->reserved->block, ctx->key);

		/* Write back the block to the output. */
		memcpy(out, ctx->reserved->block, ctx->primitive->szBlock);
		*outlen += ctx->primitive->szBlock;
		out += ctx->primitive->szBlock;

		/* Go forward in the input buffer. */
		inlen -= ctx->primitive->szBlock - ctx->reserved->available;
		in += ctx->primitive->szBlock - ctx->reserved->available;
		ctx->reserved->available = 0;
	}

	/* Save the final block. */
	memcpy(ctx->reserved->block + ctx->reserved->available, in, inlen);
	ctx->reserved->available += inlen;

	/* We're done. */
	return true;

	/* This is an old, more explicit but (hopefully) equivalent version. Keep for reference. */
	#ifdef COMMENT
	/* If the final data is less than or equal to a full block size, save it. */
	if (ctx->reserved->available + inlen <= ctx->primitive->szBlock)
	{
		memcpy(ctx->reserved->block + ctx->reserved->available, in, inlen);
		ctx->reserved->available += inlen;
	}
	else
	{
		/* Otherwise, process the available block and save the remaining part. */
		memcpy(ctx->reserved->block + ctx->reserved->available, in, ctx->primitive->szBlock - ctx->reserved->available);

		/* Decrypt the block. */
		ctx->primitive->fInverse(ctx->reserved->block, ctx->key);

		/* Write back the block to the output. */
		memcpy(out, ctx->reserved->block, ctx->primitive->szBlock);
		out += ctx->primitive->szBlock;
		(*outlen) += ctx->primitive->szBlock;

		/* Go forward in the input buffer. */
		in += ctx->primitive->szBlock - ctx->reserved->available;
		inlen -= ctx->primitive->szBlock - ctx->reserved->available;
		ctx->reserved->available = 0;

		/* Copy the rest. */
		memcpy(ctx->reserved->block + ctx->reserved->available, in, inlen);
		ctx->reserved->available += inlen;
	}
	#endif
}

/*! Finalizes an encryption context in ECB mode. The context must have been allocated and initialized.
  \param ctx The initialized encryption context.
  \param out A pointer to the final plaintext/ciphertext buffer.
  \param outlen A pointer to an integer which will contain the amount of plaintext output, in bytes.
  \param decrypt Describes whether to perform decryption or encryption.
  \return Returns true on success, false on failure.
  \remark The out buffer must have enough space to accomodate up to one block size of plaintext for padding. */
bool ECB_EncryptFinal(ECB_ENCRYPT_CONTEXT* ctx, unsigned char* out, size_t* outlen)
{
	/* Compute the amount of padding required. */
	unsigned char padding = ctx->primitive->szBlock - ctx->reserved->available % ctx->primitive->szBlock;

	/* Write padding to the last block. */
	memset(ctx->reserved->block + ctx->reserved->available, padding, padding);

	/* Encrypt the last block. */
	ctx->primitive->fPermutation(ctx->reserved->block, ctx->key);

	/* Write it out to the buffer. */
	memcpy(out, ctx->reserved->block, ctx->primitive->szBlock);
	*outlen = ctx->primitive->szBlock;

	/* Return success. */
	return true;
}

bool ECB_DecryptFinal(ECB_ENCRYPT_CONTEXT* ctx, unsigned char* out, size_t* outlen)
{
	unsigned char padding;

	/* Otherwise, decrypt the last block. */
	ctx->primitive->fInverse(ctx->reserved->block, ctx->key);

	/* Read the amount of padding. */
	padding = *(ctx->reserved->block + ctx->primitive->szBlock - 1);

	/* Check the padding. */
	if ((padding != 0) && (padding <= ctx->primitive->szBlock))
	{
		if (padcheck(ctx->reserved->block + ctx->primitive->szBlock - padding, padding))
		{
			*outlen = ctx->primitive->szBlock - padding;
			memcpy(out, ctx->reserved->block, *outlen);
		}
		else return false;
	} else return false;

	/* Return success. */
	return true;
}

void ECB_Free(ECB_ENCRYPT_CONTEXT* ctx)
{
	/* Allocate context fields. */
	sfree(ctx->reserved->block, ctx->primitive->szBlock);
	sfree(ctx->reserved, sizeof(RESERVED));
	sfree(ctx->key, ctx->primitive->szKey);
}

/* Fills a ENCRYPT_MODE struct with the correct information. */
void ECB_SetMode(ENCRYPT_MODE** mode)
{
	(*mode) = malloc(sizeof(ENCRYPT_MODE));
	(*mode)->fCreate = &ECB_Create;
	(*mode)->fInit = &ECB_Init;
	(*mode)->fEncryptUpdate = &ECB_EncryptUpdate;
	(*mode)->fDecryptUpdate = &ECB_DecryptUpdate;
	(*mode)->fEncryptFinal = &ECB_EncryptFinal;
	(*mode)->fDecryptFinal = &ECB_DecryptFinal;
	(*mode)->fFree = &ECB_Free;
	(*mode)->name = "ECB";
}