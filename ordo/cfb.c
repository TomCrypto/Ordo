/**
 * @file CFB.c
 * Implements the CFB mode of operation. CFB is a streaming mode of operation which performs no padding and works
 * similarly to the OFB mode of operation, except the keystream is exclusive-or'ed with the plaintext before being
 * fed back into the permutation function (whereas OFB is fed back immediately). Therefore the CFB keystream is
 * dependent on the plaintext.
 *
 * @see CFB.h
 */

#include "primitives.h"
#include "encrypt.h"
#include "cfb.h"

/*! This is extra context space required by the CFB mode to store the amount of state not used.*/
typedef struct RESERVED
{
	/*! The amount of bytes of unused state remaining before the state is to be renewed. */
	size_t remaining;
} RESERVED;

/*! This structure describes a symmetric encryption context for the OFB mode. */
typedef struct CFB_ENCRYPT_CONTEXT
{
	/*! The primitive to use. */
	CIPHER_PRIMITIVE* primitive;
	/*! The mode of operation to use (this is set to the OFB mode). */
	struct ENCRYPT_MODE* mode;
	/*! Points to the key material. */
	void* key;
	/*! Points to the initialization vector. */
	void* iv;
	/*! Whether to encrypt or decrypt (true = encryption). */
	bool direction;
	/*! Whether padding is enabled or not. */
	bool padding;
	/*! Reserved space for the OFB mode of operation. */
	RESERVED* reserved;
} CFB_ENCRYPT_CONTEXT;

void CFB_Create(CFB_ENCRYPT_CONTEXT* ctx)
{
	/* Allocate context space. */
	ctx->key = salloc(ctx->primitive->szKey);
	ctx->iv = salloc(ctx->primitive->szBlock);
	ctx->reserved = salloc(sizeof(RESERVED));
}

/*! Initializes an OFB context (the primitive and mode must have been filled in).
  \param ctx The initialized encryption context.
  \param key A pointer to the key to use for encryption.
  \param keySize The size, in bytes, of the key.
  \param tweak The tweak to use (this may be zero, depending on the primitive).
  \param iv The initialization vector to use.
  \return Returns true on success, false on failure. */
bool CFB_Init(CFB_ENCRYPT_CONTEXT* ctx, void* key, size_t keySize, void* tweak, void* iv)
{
	/* Check the key size. */
	if (!ctx->primitive->fKeyCheck(keySize)) return false;

	/* Copy the IV (required) into the context IV. */
	memcpy(ctx->iv, iv, ctx->primitive->szBlock); 

	/* Perform the key schedule. */
	if (!ctx->primitive->fKeySchedule(key, keySize, tweak, ctx->key)) return false;

	/* Compute the initial keystream block. */
	ctx->primitive->fPermutation(ctx->iv, ctx->key);
	ctx->reserved->remaining = ctx->primitive->szBlock;

	/* Return success. */
	return true;
}

/*! Encrypts a buffer in OFB mode. The context must have been allocated and initialized.
  \param ctx The initialized encryption context.
  \param in A pointer to the plaintext buffer.
  \param inlen The size of the plaintext buffer, in bytes.
  \param out A pointer to the ciphertext buffer.
  \param outlen A pointer to an integer which will contain the amount of ciphertext output, in bytes.
  \return Returns true on success, false on failure.
  \remark The out buffer must be the same size as the in buffer, as OFB is a streaming mode. */
bool CFB_EncryptUpdate(CFB_ENCRYPT_CONTEXT* ctx, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
{
	/* Initialize the output size. */
	*outlen = 0;

	/* Go over the buffer byte per byte. */
	while (inlen != 0)
	{
		/* If there is no data left in the context block, update. */
		if (ctx->reserved->remaining == 0)
		{
			/* CFB update (simply apply the permutation function again). */
			ctx->primitive->fPermutation(ctx->iv, ctx->key);
			ctx->reserved->remaining = ctx->primitive->szBlock;
		}

		/* XOR the plaintext byte with the keystream before feeding back! */
		*out = *((unsigned char*)ctx->iv + ctx->primitive->szBlock - ctx->reserved->remaining) ^ *in;
		*((unsigned char*)ctx->iv + ctx->primitive->szBlock - ctx->reserved->remaining) = *out;

		ctx->reserved->remaining--;
		in++;
		out++;
		inlen--;
		(*outlen)++;
	}

	/* Return success. */
	return true;
}

/*! Decrypts a buffer in OFB mode. The context must have been allocated and initialized.
  \param ctx The initialized encryption context.
  \param in A pointer to the ciphertext buffer.
  \param inlen The size of the ciphertext buffer, in bytes.
  \param out A pointer to the plaintext buffer.
  \param outlen A pointer to an integer which will contain the amount of plaintext output, in bytes.
  \return Returns true on success, false on failure.
  \remark The out buffer must be the same size as the in buffer, as OFB is a streaming mode.  */
bool CFB_DecryptUpdate(CFB_ENCRYPT_CONTEXT* ctx, unsigned char* in, size_t inlen, unsigned char* out, size_t* outlen)
{
	/* Initialize the output size. */
	*outlen = 0;

	/* Go over the buffer byte per byte. */
	while (inlen != 0)
	{
		/* If there is no data left in the context block, update. */
		if (ctx->reserved->remaining == 0)
		{
			/* CFB update (simply apply the permutation function again). */
			ctx->primitive->fPermutation(ctx->iv, ctx->key);
			ctx->reserved->remaining = ctx->primitive->szBlock;
		}

		/* XOR the plaintext byte with the keystream, and use the original ciphertext as the next keystream block input. */
		*out = *((unsigned char*)ctx->iv + ctx->primitive->szBlock - ctx->reserved->remaining) ^ *in;
		*((unsigned char*)ctx->iv + ctx->primitive->szBlock - ctx->reserved->remaining) = *in;

		ctx->reserved->remaining--;
		in++;
		out++;
		inlen--;
		(*outlen)++;
	}

	/* Return success. */
	return true;
}

/*! Finalizes an encryption context in OFB mode. The context must have been allocated and initialized.
  \param ctx The initialized encryption context.
  \param out Set this to zero as the OFB mode uses no padding.
  \param outlen Set this to null.
  \param decrypt Unused parameter.
  \return Returns true on success, false on failure. */
bool CFB_Final(CFB_ENCRYPT_CONTEXT* ctx, unsigned char* out, size_t* outlen)
{
	/* Write output size if applicable. */
	if (outlen != 0) *outlen = 0;

	/* Return true. */
	return true;
}

void CFB_Free(CFB_ENCRYPT_CONTEXT* ctx)
{
	/* Free context space. */
	sfree(ctx->reserved, sizeof(RESERVED));
	sfree(ctx->iv, ctx->primitive->szBlock);
	sfree(ctx->key, ctx->primitive->szKey);
}

/* Fills a ENCRYPT_MODE struct with the correct information. */
void CFB_SetMode(ENCRYPT_MODE** mode)
{
	(*mode) = malloc(sizeof(ENCRYPT_MODE));
	(*mode)->fCreate = &CFB_Create;
	(*mode)->fInit = &CFB_Init;
	(*mode)->fEncryptUpdate = &CFB_EncryptUpdate;
	(*mode)->fDecryptUpdate = &CFB_DecryptUpdate;
	(*mode)->fEncryptFinal = &CFB_Final;
	(*mode)->fDecryptFinal = &CFB_Final;
	(*mode)->fFree = &CFB_Free;
	(*mode)->name = "CFB";
}